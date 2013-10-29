#!/usr/bin/python2.6
import sys

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print "filename"
        sys.exit(1)
    print sys.argv[1], sys.argv[2], sys.argv[3]
    recv = open(sys.argv[1]).readlines()
    send = open(sys.argv[2]).readlines()
    result = open(sys.argv[3], 'w')
    
    recv = [x.strip().split(' ') for x in recv]
    recv = [[x[0], x[1]] for x in recv]
    send = [x.strip().split(' ') for x in send]
    send = [[x[0], x[1]] for x in send]

    total = 0
    min = 100000
    max = 0
    for x in recv:
        for y in send:
            if y[0] == x[0]:
                res = int(x[1]) - int(y[1])
                total += res
                if min > res:
                    min = res
                if max < res:
                    max = res
                result.write(str(res) + '\n')
    print total/len(recv), min, max
