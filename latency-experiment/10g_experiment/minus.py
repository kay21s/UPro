#!/usr/bin/python2.6
import sys

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print "need recv, send, result filename"
        sys.exit(1)
    print sys.argv[1], sys.argv[2], sys.argv[3]
    recv = open(sys.argv[1]).readlines()
    send = open(sys.argv[2]).readlines()
    result = open(sys.argv[3], 'w')
    total = 0
    for i in range(len(recv)):
        #print recv[i].strip().split(' ')[0]
        res = int(recv[i].strip().split(' ')[0]) - int(send[i].strip().split(' ')[0])
        total += res
        result.write(str(res))
        result.write('\n')
    print total/len(recv)
