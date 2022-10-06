# Compare TLS stacks

The goal of this repo is to test how well the tls stacks of
[utls](https://github.com/refraction-networking/utls) and
[utls-light](https://github.com/hellais/utls-light) work with [servers measured by ooni](https://github.com/citizenlab/test-lists/).

The intent is that of understanding if and how they break with certain TLS
server configurations.

The checks can be run via:
```
go run compare-stacks.go
```

You can also pass in some flags:
```
go run compare-stacks.go -domains=domain-list.txt -parallelism=42
```

You will then have a CSV file with the following columns `server_name,err_flags,err_tls,err_utls,err_utlslight,ts`:
* `server_name` is the domain name tested
* `err_flags` is a bitmask with a flag set to 1 if the relative tls stack failed (`x y z` where the bit indicates if golang tls failed, utls failed or utls-light failed respectively, ex. 7 means they all failed, 4 means only utls-light failed)
* `err_tls` is the error string, if present, for golang-tls
* `err_utls` is the error string, if present, for utls
* `err_utlslight` is the error string, if present, for utls-light
