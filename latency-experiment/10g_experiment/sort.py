#!/usr/bin/python2.6
import sys

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "filename"
        sys.exit(1)
    print sys.argv[1], sys.argv[2]
    input = open(sys.argv[1]).readlines()
    output = open(sys.argv[2], 'w')
    
    input = [x.strip().split(' ') for x in input]
    input = [[x[0], x[1]] for x in input]

    res = [[int(x[0]), int(x[1])] for x in input]
    res.sort()
    res = [str(x[0]) + ' ' + str(x[1]) + '\n' for x in res]
    output.writelines(res)

    output.close()
