#!/usr/bin/python
import os

speed = 10000000000  #10Gbps
total_pkt = speed/(8*1328) # how many packets per second

#set I from 10 to 500
startI = 10.0
endI = 62.0

def drange(start, stop, step):
	r = start
	while r < stop:
		yield r
		r += step


for stream in range(1, 7):
	print stream
	result_file = open("result"+str(stream), "w+")
	time_list = drange(startI, endI, 2.0)
	for time in time_list:
		pkt_num = int(total_pkt * (time/1000))
		cmd = r'./run ' + str(pkt_num/stream) + ' ' + str(stream)
		output = os.popen(cmd).read().strip()
		result_file.write(str(int(time))+' '+output+'\n')
		print time, stream
