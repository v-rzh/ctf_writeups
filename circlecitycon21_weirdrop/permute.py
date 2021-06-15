#!/usr/bin/env python3

import sys
from itertools import permutations

xors = [ 0x16b, 0x188, 0x198, 0x19b, 0x1a3, 0x1a9, 0x1d, 0x1e5, 0x1f4, 0x237,
         0x25, 0x274, 0x281, 0x28e, 0x29a, 0x2b3, 0x30c, 0x314, 0x32e, 0x355,
         0x3ab, 0x3cd, 0x6f, 0xc1, 0x56, 0x53]

def permute(target):
    for i in range(2, len(xors)):
        p = permutations(xors, i)
        for j in list(p):
            res = 0
            for k in j:
                res ^= k;
                if res == target:
                    return j;
    return ()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"{sys.argv[0]} target_number")

    res = permute(int(sys.argv[1]))
    for i in res:
        print(hex(i) + " ", end='')

    print("")
