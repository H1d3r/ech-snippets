BINARY_NAME=ech-tunnel
WORKERS_NAME=ech-workers
BUILD_LDFLAGS=-s -w

mac:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="${BUILD_LDFLAGS}" -o "./bin/${BINARY_NAME}" ech-tunnel.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="${BUILD_LDFLAGS}" -o "./bin/${WORKERS_NAME}" ech-workers.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="${BUILD_LDFLAGS}" -o "./bin/${BINARY_NAME}_arm64" ech-tunnel.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="${BUILD_LDFLAGS}" -o "./bin/${WORKERS_NAME}_arm64" ech-workers.go

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="${BUILD_LDFLAGS}" -o "./bin/${BINARY_NAME}_Linux" ech-tunnel.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="${BUILD_LDFLAGS}" -o "./bin/${WORKERS_NAME}_Linux" ech-workers.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="${BUILD_LDFLAGS}" -o "./bin/${BINARY_NAME}_Linux_arm64" ech-tunnel.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="${BUILD_LDFLAGS}" -o "./bin/${WORKERS_NAME}_Linux_arm64" ech-workers.go
win:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="${BUILD_LDFLAGS}" -o "./bin/${BINARY_NAME}_win_amd64.exe" ech-tunnel.go
run:
	go build -o ${BINARY_NAME} ech-tunnel.go
	./${BINARY_NAME}

clean:
	go clean
	rm -rf bin

upx:
	upx ./bin/* 

all: mac linux win upx
