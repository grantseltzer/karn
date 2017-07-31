#!/bin/bash

export GOROOT=/usr/local/go
export GOPATH=""
UNIT_TEST_PKG_FILE="./tests/packages_to_test.txt"
UNIT_TEST_PREFIX="github.com/GrantSeltzer/karn"
PKGS_TO_TEST=`cat $UNIT_TEST_PKG_FILE | grep -v '#'`
RET=0

setupFakeGoWorkspace() {
    CUR_DIR=`pwd`
    export GOPATH=`mktemp -d`
    cd $GOPATH
    /bin/mkdir ./src
    /bin/mkdir ./pkg
    /bin/mkdir ./bin

    /bin/mkdir -p ./src/github.com/GrantSeltzer
    echo "Symlinking repo $CUR_DIR to $GOPATH/src/$UNIT_TEST_PREFIX"
    ln -s $CUR_DIR ./src/$UNIT_TEST_PREFIX
}

cleanUp() {
    echo "Cleaning up $GOPATH"
    rm -rf $GOPATH
}

runTests() {
    echo "GOPATH: $GOPATH"
    cd $GOPATH/src/$UNIT_TEST_PREFIX
    for package in $PKGS_TO_TEST; do
      if [[ $package != "#*" ]]; then
        echo $PWD
        ls tests/golden_files/output
        go1.9beta2 test -tags=testing "$UNIT_TEST_PREFIX/$package"
        if [ "$?" != "0" ]; then
          RET=1
        fi
      fi
    done
}

setupFakeGoWorkspace
runTests
cleanUp
exit $RET% 