package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"crypto/tls"

	utlslight "github.com/hellais/utls-light/tls"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var ErrDNSResolution = errors.New("unable to lookup IP")
var ErrConnect = errors.New("unable to connect")
var ErrTimeout = errors.New("timeout reached")

type clientFunc func(conn net.Conn, serverName string) (net.Conn, error, string)

func uTLSLightClientFunc(conn net.Conn, serverName string) (net.Conn, error, string) {
	config := utlslight.Config{ServerName: serverName, NextProtos: []string{"h2", "http/1.1"}}
	tlsConn := utlslight.Client(conn, &config)

	err := tlsConn.Handshake()
	negotiatedProtocol := tlsConn.ConnectionState().NegotiatedProtocol
	return tlsConn, err, negotiatedProtocol
}

func uTLSClientFunc(conn net.Conn, serverName string) (net.Conn, error, string) {
	config := utls.Config{ServerName: serverName, NextProtos: []string{"h2", "http/1.1"}}
	tlsConn := utls.UClient(conn, &config, utls.HelloChrome_102)

	err := tlsConn.Handshake()
	negotiatedProtocol := tlsConn.ConnectionState().NegotiatedProtocol
	return tlsConn, err, negotiatedProtocol
}

func tlsClientFunc(conn net.Conn, serverName string) (net.Conn, error, string) {
	config := tls.Config{ServerName: serverName, NextProtos: []string{"h2", "http/1.1"}}
	tlsConn := tls.Client(conn, &config)

	err := tlsConn.Handshake()
	negotiatedProtocol := tlsConn.ConnectionState().NegotiatedProtocol
	return tlsConn, err, negotiatedProtocol
}

func getRequest(conn net.Conn, url *url.URL, alpn string) (*http.Response, error) {
	req := &http.Request{
		Method: "GET",
		URL:    url,
		Header: make(http.Header),
		Host:   url.Hostname(),
	}

	switch alpn {
	case "h2":
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0

		tr := http2.Transport{}
		cConn, err := tr.NewClientConn(conn)
		if err != nil {
			return nil, err
		}
		return cConn.RoundTrip(req)
	case "http/1.1", "":
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		err := req.Write(conn)
		if err != nil {
			return nil, err
		}
		return http.ReadResponse(bufio.NewReader(conn), req)
	default:
		return nil, fmt.Errorf("unsupported ALPN: %v", alpn)
	}
}

func testDomain(serverName string, addr string, perform clientFunc) error {
	dialConn, err := net.DialTimeout("tcp", addr, time.Duration(2)*time.Second)
	if err != nil {
		return ErrConnect
	}

	tlsConn, err, negotiatedProtocol := perform(dialConn, serverName)
	defer tlsConn.Close()
	if err != nil {
		return err
	}
	reqURL, _ := url.Parse(fmt.Sprintf("https://%s/", serverName))

	_, err = getRequest(tlsConn, reqURL, negotiatedProtocol)

	return err
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type ComparisonResult struct {
	serverName   string
	addr         string
	errTLS       error
	errUTLS      error
	errUTLSLight error
	ts           int64
}

func NewComparisonResult(serverName string, addr string, errTLS error, errUTLS error, errUTLSLight error) *ComparisonResult {
	return &ComparisonResult{
		serverName:   serverName,
		addr:         addr,
		errTLS:       errTLS,
		errUTLS:      errUTLS,
		errUTLSLight: errUTLSLight,
		ts:           time.Now().Unix(),
	}
}

func (c *ComparisonResult) BitMask() int {
	errFlags := 0
	if c.errTLS != nil {
		errFlags |= 1
	}
	if c.errUTLS != nil {
		errFlags |= (1 << 1)
	}
	if c.errUTLSLight != nil {
		errFlags |= (1 << 2)
	}
	return errFlags
}

func compareResults(ctx context.Context, ch chan *ComparisonResult, serverName string) {
	ips, err := net.LookupIP(serverName)
	// If we fail to lookup the serverName, we don't do anything
	if len(ips) == 0 || err != nil {
		ch <- NewComparisonResult(serverName, "", ErrDNSResolution, ErrDNSResolution, ErrDNSResolution)
		return
	}

	addr := fmt.Sprintf("%s:443", ips[0].String())
	errTLS := testDomain(serverName, addr, tlsClientFunc)
	// If we fail to connect, we just consider the host to be unreachable
	if errors.Is(errTLS, ErrConnect) {
		ch <- NewComparisonResult(serverName, addr, errTLS, errTLS, errTLS)
		return
	}

	errUTLS := testDomain(serverName, addr, uTLSClientFunc)
	errUTLSLight := testDomain(serverName, addr, uTLSLightClientFunc)
	ch <- NewComparisonResult(serverName, addr, errTLS, errUTLS, errUTLSLight)
}

func main() {
	parallelism := flag.Int("pallelism", 100, "how many requests should be done concurrently")
	timeout := flag.Int("timeout", 20, "maximum timeout in seconds after which to give out testing")
	domainFile := flag.String("domains", "citizenlab-domains.txt", "list of domains to test")

	file, err := os.Open(*domainFile)
	if err != nil {
		panic("unable to open file")
	}
	defer file.Close()

	outFile, err := os.Create(fmt.Sprintf("comparison-%d.csv", time.Now().Unix()))
	if err != nil {
		panic("unable to open csv file")
	}
	csvWriter := csv.NewWriter(outFile)
	defer csvWriter.Flush()
	defer outFile.Close()
	_ = csvWriter.Write([]string{
		"server_name",
		"addr",
		"err_flags",
		"err_tls",
		"err_utls",
		"err_utlslight",
		"ts",
	})

	wg := &sync.WaitGroup{}
	wgWriter := &sync.WaitGroup{}
	chServerName := make(chan string)
	chResults := make(chan *ComparisonResult)

	go func() {
		defer close(chServerName)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			serverName := scanner.Text()
			chServerName <- serverName
		}
	}()

	for i := 0; i < *parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for serverName := range chServerName {
				ch := make(chan *ComparisonResult, 1)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(*timeout))
				go compareResults(ctx, ch, serverName)

				select {
				case <-ctx.Done():
					chResults <- NewComparisonResult(serverName, "", ErrTimeout, ErrTimeout, ErrTimeout)
				case result := <-ch:
					chResults <- result
				}
				cancel()
			}
		}()
	}

	wgWriter.Add(1)
	go func() {
		defer wgWriter.Done()
		for res := range chResults {
			_ = csvWriter.Write([]string{
				res.serverName,
				res.addr,
				fmt.Sprintf("%d", res.BitMask()),
				errStr(res.errTLS),
				errStr(res.errUTLS),
				errStr(res.errUTLSLight),
				fmt.Sprintf("%d", res.ts),
			})
			csvWriter.Flush()

			fmt.Printf("%s,%s,%d,%s,%s,%s\n",
				res.serverName,
				res.addr,
				res.BitMask(),
				errStr(res.errTLS),
				errStr(res.errUTLS),
				errStr(res.errUTLSLight),
			)
		}
	}()

	wg.Wait()
	close(chResults)
	wgWriter.Wait()
}
