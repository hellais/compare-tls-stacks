package main

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"crypto/tls"
	utlslight "github.com/hellais/utls-light/tls"
	utls "github.com/refraction-networking/utls"
)

var ErrDNSResolution = errors.New("unable to lookup IP")
var ErrConnect = errors.New("unable to connect")

type clientFunc func(net.Conn, string) error

func uTLSLightClientFunc(conn net.Conn, serverName string) error {
	config := utlslight.Config{ServerName: serverName, NextProtos: []string{"h2", "http/1.1"}}
	tlsConn := utlslight.Client(conn, &config)
	defer tlsConn.Close()
	return tlsConn.Handshake()
}

func uTLSClientFunc(conn net.Conn, serverName string) error {
	config := utls.Config{ServerName: serverName, NextProtos: []string{"h2", "http/1.1"}}
	tlsConn := utls.UClient(conn, &config, utls.HelloChrome_102)
	defer tlsConn.Close()
	return tlsConn.Handshake()
}

func tlsClientFunc(conn net.Conn, serverName string) error {
	config := tls.Config{ServerName: serverName, NextProtos: []string{"h2", "http/1.1"}}
	tlsConn := tls.Client(conn, &config)
	defer tlsConn.Close()
	return tlsConn.Handshake()
}

func testDomain(serverName string, addr string, makeHandshake clientFunc) error {
	dialConn, err := net.DialTimeout("tcp", addr, time.Duration(2)*time.Second)
	if err != nil {
		return ErrConnect
	}
	return makeHandshake(dialConn, serverName)
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func compareResults(serverName string) (error, error, error) {
	ips, err := net.LookupIP(serverName)
	// If we fail to lookup the serverName, we don't do anything
	if len(ips) == 0 || err != nil {
		return ErrDNSResolution, ErrDNSResolution, ErrDNSResolution
	}

	addr := fmt.Sprintf("%s:443", ips[0].String())
	errTLS := testDomain(serverName, addr, tlsClientFunc)
	// If we fail to connect, we just consider the host to be unreachable
	if errors.Is(errTLS, ErrConnect) {
		return errTLS, errTLS, errTLS
	}

	errUTLS := testDomain(serverName, addr, uTLSClientFunc)
	errUTLSLight := testDomain(serverName, addr, uTLSLightClientFunc)
	return errTLS, errUTLS, errUTLSLight
}

func main() {
	file, err := os.Open("citizenlab-domains.txt")
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
		"err_flags",
		"err_tls",
		"err_utls",
		"err_utlslight",
		"ts",
	})

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		serverName := scanner.Text()
		errTLS, errUTLS, errUTLSLight := compareResults(serverName)

		errFlags := 0
		if errTLS != nil {
			errFlags |= 1
		}
		if errUTLS != nil {
			errFlags |= (1 << 1)
		}
		if errUTLSLight != nil {
			errFlags |= (1 << 2)
		}

		_ = csvWriter.Write([]string{
			serverName,
			fmt.Sprintf("%d", errFlags),
			errStr(errTLS),
			errStr(errUTLS),
			errStr(errUTLSLight),
			fmt.Sprintf("%d", time.Now().Unix()),
		})
		csvWriter.Flush()

		fmt.Printf("%s,%d,%s,%s,%s\n",
			serverName,
			errFlags,
			errStr(errTLS),
			errStr(errUTLS),
			errStr(errUTLSLight),
		)
	}
}
