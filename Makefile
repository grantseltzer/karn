default: karn-cli

.PHONY: karn-cli
karn-cli:
	mkdir -p ./bin
	go build -o ./bin/karn ./cmd/cli

.PHONY: c
c:
	go build -mod=vendor -o ./bin/karn.so -buildmode=c-shared ./c/main.go

clean:
	rm ./bin/*

help:
	@echo  "Targets:"
	@echo  "    karn-cli (default) - build karn cli to ./bin/karn"
	@echo  "    c - create karn.so and karn.h files
	@echo  "    clean - remove bin contents"
