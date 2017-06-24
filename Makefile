# Karn makefile
# Author: Grant Seltzer (grant@capsule8.com)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOINSTALL=$(GOCMD) install
GOTEST=$(GOCMD) test
GODEP=$(GOTEST) -i
GOFMT=gofmt -w
GOVET=go tool vet

VERSION="0.0.1"
BUILD=`git rev-parse HEAD`
BINARY="karn"

.PHONY: build man clean install test fmt vet help

all: build man

build:
	$(GOBUILD) -o ./dist/$(BINARY) .
man:
	gzip -fk karn.1
clean:
	rm dist/*
install:
	$(GOINSTALL) -o $(BINARY) ./...
fmt: 
	$(GOFMT) ./...
vet:
	$(GOVET) --all ./$*
help:
	@echo "$(BINARY) Makefile Available targets"
	@echo "----"
	@echo "all: Builds the code"
	@echo "man": Generate man page
	@echo "build: Builds the code"
	@echo "fmt: Formats the source files using gofmt"
	@echo "clean: cleans the code"
	@echo ""

