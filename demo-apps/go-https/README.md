# Web App: Go HTTPS
This is a https-web app, written by Golang and copy from `pixie-io/pixie`.
## build
```bash
go version
go version go1.20.7 linux/amd64
go build https_server.go
```
## run
```bash
# run 1
./https_server
2023/12/21 15:57:34 Starting HTTP service on Port 50100
2023/12/21 15:57:34 Starting HTTPS service on Port 50101
# run 2
./https_server --key=server.key --cert=server.crt
2023/12/21 15:58:56 Starting HTTP service on Port 50100
2023/12/21 15:58:56 Starting HTTPS service on Port 50101
```
## test
```bash
curl -k --http1.1 https://localhost:50101
{"status":"ok"}
```