#include "karn.h"
#include <unistd.h>
#include <stdio.h>

int main() {

    GoString chownName = {"chown", 5};
    GoSlice entitlementNames = {&chownName, 1, 1};
    int err = ApplyEntitlementsByName(entitlementNames);
    if (err == -1) {
        printf("error\n");
    }

    int err2 = chown("./testfile.txt", 0, 0);    
    if (err == -1) {
        printf("error2\n");
    }
}