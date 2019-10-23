#!/bin/bash

rm karnTest karn.h karn.so testfile.txt
echo hi > testfile.txt
go build -mod=vendor -o karn.so -buildmode=c-shared main.go
gcc -o karnTest ./karn.c ./karn.so
