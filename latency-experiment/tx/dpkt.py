import dpkt
import sys
f = file(sys.argv[1], "rb")
pcap=dpkt.pcap.Reader(f)

ts,buf = pcap[0]
eth = dpkt.ethernet.Ethernet(buf)
ip= eth.data

m = file(sys.argv[2], "w")
m.write(ip)

f.close()
m.close()
