#!/bin/bash

go build -mod=vendor -o karn.so -buildmode=c-shared main.go
if [ $? -ne 0 ]; then
    echo failed to build shared object
    exit -1
fi 
