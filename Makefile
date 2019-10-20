default: karn-cli

.PHONY: karn-cli
karn-cli:
	mkdir -p ./bin
	go build -o ./bin/karn ./cmd/cli

clean:
	rm ./bin/*

help:
	@echo  "just type 'make' to build the karn cli. test target coming soon" 