#!/usr/bin/python2.6
import sys

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "need file name"
        sys.exit(1)
    print sys.argv[1]
    recv = open(sys.argv[1]).readlines()
    total = 0
    min = 100000
    max = 0
    for i in range(len(recv)):
        #print recv[i].strip().split(' ')[0]
        res = int(recv[i].strip().split(' ')[0])
        total += res
        if min > res:
            min = res
        if max < res:
            max = res
    print total/len(recv), min, max
