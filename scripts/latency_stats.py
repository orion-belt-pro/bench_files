#import stl_path
from trex.stl.api import *
import time
import pprint
from scapy.contrib.gtp import *
from trex_stl_lib.api import *
import csv

def rx_example (tx_port, rx_port, burst_size, pps, packet_len):
    # create client
    c = STLClient()
    passed = True
    direction = ""
    test = ""
    streams = []

    try:
	"""
#       Test1 = Varying packet size (Fixed per test)
#       Test2 = Varying packet size (Distributed per test -> 20% low(100Byte), 60% medium(1024Byte), 20% high(1536Byte))
#       Test3 = Varying pps (Fixed per test)
#       Test4 = Varying flow (Fixed per test)

#       Direction = uplink or downlink 
	"""
        test="Test1"
        direction="uplink"

        vm_src = STLScVmRaw([STLVmFlowVar(name="ip_src",
                           min_value="8.8.8.1",
                           max_value="8.8.8.10",
                         size=4, op="inc"),
                           STLVmWrFlowVar(fv_name="ip_src", pkt_offset= "IP.src"),
                           STLVmFixIpv4(offset = "IP"),
                           ])

        vm_dst = STLScVmRaw([STLVmFlowVar(name="ip_dst",
                           min_value="8.8.8.1",
                           max_value="8.8.8.10",
                         size=4, op="inc"),
                           STLVmWrFlowVar(fv_name="ip_dst", pkt_offset= "IP:1.dst"),
                           STLVmFixIpv4(offset = "IP:1"),
                           ])
	test="Test1"
        direction="uplink"

        if direction == "uplink": 
#		uplink gtp packet
#        	pkt = Ether()/IP(src="172.20.16.99",dst="172.20.16.105")/UDP(dport=2152)/GTP_U_Header(teid=1234)/IP(src="10.10.10.10",dst="172.20.16.55",version=4,id=0xFFFF)/UDP()/'at_least_16_bytes_payload_needed'
        	pkt = Ether()/IP(src="172.20.16.99",dst="172.20.16.105")/UDP(dport=2152)/GTP_U_Header(teid=1234)/IP(src="10.10.10.10",version=4,id=0xFFFF)/UDP()/'at_least_16_bytes_payload_needed'
                vm = vm_dst
	else:
#       	downlink packet 
#        	pkt = Ether()/IP(src="172.20.16.55",dst="10.10.10.10",version=4,id=0xFFFF)/UDP()/'at_least_16_bytes_payload_needed'
                pkt = Ether()/IP(dst="10.10.10.10",version=4,id=0xFFFF)/UDP()/'at_least_16_bytes_payload_needed'
		vm = vm_src
		pkt /= 'x' * 36
        total_pkts = burst_size
        print("Length of the packet",len(pkt))
        pkt /= 'x' * packet_len
	packet = STLPktBuilder(pkt =pkt, vm=vm)
        print("Length of the packet after padding",len(pkt))

	if test == "Test1":
		print(" ##### Test 1 : Varying packet size (fixed per test) #####")
        	s1 = STLStream(name = 'stram1',
                		packet = packet,
                       		flow_stats = STLFlowLatencyStats(pg_id = 5),
                       		mode = STLTXCont(pps=pps)) 
                streams = [s1] 

	if test == "Test2":
        	print(" ##### Test 2 : Varying packet size (distribution) #####")  
        	s1 = STLStream(name = 'stram1',
                       		packet = packet,
                       		flow_stats = STLFlowLatencyStats(pg_id = 5),
                       		mode = STLTXCont(pps=pps*0.2))
                print("Stream1: Length of the packet",len(pkt))

        	pkt /= 'x' * 914
        	packet = STLPktBuilder(pkt =pkt, vm= vm)
        	s2 = STLStream(name = 'stream2',
                       		packet = packet,
                       		flow_stats = STLFlowLatencyStats(pg_id = 6),
                       		mode = STLTXCont(pps=pps*0.6))
        	print("Stream2: Length of the packet",len(pkt))

        	pkt /= 'x' * 512
        	packet = STLPktBuilder(pkt =pkt, vm= vm)
        	s3 = STLStream(name = 'stream3',
                       		packet = packet,
                       		flow_stats = STLFlowLatencyStats(pg_id = 7),
                       		mode = STLTXCont(pps=pps*0.2))

        	print("S3: Length of the packet",len(pkt))
	        streams = [s1, s2, s3]
	"""
#      Test 4 : Varying packet flow (distribution)
	pkt /= 'x' * packet_len
        packet = STLPktBuilder(pkt =pkt, vm = vm)
        s4 = STLStream(name = 'stram4',
                       packet = packet,
                       flow_stats = STLFlowLatencyStats(pg_id =  5),
                       mode = STLTXCont(pps=pps))
#                      mode = STLTXSingleBurst(total_pkts = total_pkts,
#                                              pps = pps))
	"""

        # connect to server
        c.connect()
        # prepare our ports
        c.reset(ports = [tx_port, rx_port])
        # add streams to ports
        print("\nInjecting packets \n")
        c.add_streams(streams, ports = [tx_port])
        print("All strams: Length of the packet", packet.get_pkt_len())
	i=0
	while(i<4):
		rc = rx_iteration(c, tx_port, rx_port, total_pkts, packet.get_pkt_len())
        	if not rc:
            		passed = False
		i+=1
    except STLError as e:
        passed = False
        print(e)
    finally:
        c.disconnect()
    if passed:
        print("\nTest passed :-)\n")
    else:
        print("\nTest failed :-(\n") 

def Average(lst):
    return sum(lst) / len(lst) 

# RX one iteration
def rx_iteration (c, tx_port, rx_port, total_pkts, pkt_len):
    c.clear_stats()
    c.start(ports = [tx_port])
    pgids = c.get_active_pgids()
    print ("Currently used pgids: {0}".format(pgids))
    time.sleep(1)

#    c.wait_on_traffic(ports = [rx_port])
    stats = c.get_pgid_stats(pgids['latency'])
    global_lat_stats = stats['latency']
    lat_stats = global_lat_stats.get(5)

    drops = lat_stats['err_cntrs']['dropped']
    ooo = lat_stats['err_cntrs']['out_of_order']
    dup = lat_stats['err_cntrs']['dup']
    sth = lat_stats['err_cntrs']['seq_too_high']
    stl = lat_stats['err_cntrs']['seq_too_low']
    old_flow = global_lat_stats['global']['old_flow']
    bad_hdr = global_lat_stats['global']['bad_hdr']
    lat = lat_stats['latency']
    jitter = lat['jitter']
    avg = lat['average']
    tot_max = lat['total_max']
    tot_min = lat['total_min']
    last_max = lat['last_max']
    hist = lat ['histogram']

    """
    lat_stats_s1 = global_lat_stats.get(5)      
    lat_s1=lat_stats_s1['latency']['average']    
    lat_stats_s2 = global_lat_stats.get(6) 
    lat_s2=lat_stats_s2['latency']['average']
    lat_stats_s3 = global_lat_stats.get(7) 
    lat_s3=lat_stats_s3['latency']['average']
    """

    with open("/home/rohan/bench/bench_files/logs/latency/dl/latency.csv", "a") as f:    
#        rows   = [[lat_s1],[lat_s2],[lat_s3]] 
    	writer = csv.writer(f)
        writer.writerow([avg])
#        writer.writerow(rows)
        f.close()

    if c.get_warnings():
            print("\n\n*** test had warnings ****\n\n")
            for w in c.get_warnings():
                print(w)
            return False
#    print('Error counters: dropped:{0}, ooo:{1} dup:{2} seq too high:{3} seq too low:{4}'.format(drops, ooo, dup, sth, stl))
    if old_flow:
        print ('Packets arriving too late after flow stopped: {0}'.format(old_flow))
    if bad_hdr:
        print ('Latency packets with corrupted info: {0}'.format(bad_hdr))
    print('Latency info:')
    print(" Maximum latency(usec): {0}".format(tot_max))
    print(" Minimum latency(usec): {0}".format(tot_min))
    print(" Maximum latency in last sampling period (usec): {0}".format(last_max))
    print(" Average latency(usec): {0}".format(avg))
    print(" Jitter(usec): {0}".format(jitter))
    print(" Latency distribution histogram:")
    l = hist.keys()
    l.sort()
    for sample in l:
        range_start = sample
        if range_start == 0:
            range_end = 10
        else:
            range_end = range_start + pow(10, (len(str(range_start))-1))
        val = hist[sample]
        print (" Packets with latency between {0} and {1}:{2} ".format(range_start, range_end, val))
    time.sleep(5)
    return True

#Run test
i=0
packet_len = 1
#while(i<1):
#        print("Iteration :- ", i)
#	rx_example(tx_port = 0, rx_port = 1, burst_size = 1000, pps = 400000, packet_len = 1426)
#        i+=1

rx_example(tx_port = 0, rx_port = 1, burst_size = 1000, pps = 400000, packet_len = 1426)

