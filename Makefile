all: ipinfo

deps:
	go get -d

ipinfo: deps format
	/bin/sh -c "go build -v -o ipinfo"

format:
	for directory in . iptoas; do /bin/sh -c "cd $$directory && go fmt"; done;
