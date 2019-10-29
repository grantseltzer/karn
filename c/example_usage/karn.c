#include "karn.h"
#include <unistd.h>
#include <stdio.h>

//
// This is an example of using the chown entitlement to grant
//     the running program access to the chown family of 
//     system calls. In this case, chowning to root still requires
//     running as root. If you remove the chown entitlment and 
//     compile/run as root it still wouldn't work.
//
// Must compile linking karn.so, and importing karn.h above:
//  gcc -o karnTest ./karn.c ./karn.so
//

int main() {

    GoString chownName = {"chown", 5}; // entitlement name, length of entitlement name
    GoSlice entitlementNames = {&chownName, 1, 1}; // data, length, cap

    int err = ApplyEntitlementsByName(entitlementNames);
    if (err == -1) {
        printf("error\n");
    }

    int err2 = chown("./testfile.txt", 0, 0);    
    if (err == -1) {
        printf("error2\n");
    }
}