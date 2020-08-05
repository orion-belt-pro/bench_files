# Example showing how to define stream for latency measurement, and how to parse the latency information
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

    try:
        vm = []
#	uplink gtp packet
        pkt = Ether()/IP(src="172.20.16.99",dst="172.20.16.105")/UDP(dport=2152)/GTP_U_Header(teid=1234)/IP(src="10.10.10.10",dst="172.20.16.55",version=4,id=0xFFFF)/UDP()/'at_least_16_bytes_payload_needed'
#       downlink packet 
#        pkt = Ether()/IP(src="172.20.16.55",dst="10.10.10.10",version=4,id=0xFFFF)/UDP()/'at_least_16_bytes_payload_needed' 
        total_pkts = burst_size

#        print("Length of the packet",len(pkt))
#        pkt /= 'x' * packet_len
#        print("Length of the packet",len(pkt))
	packet = STLPktBuilder(pkt =pkt, vm= vm)

	"""	
#      Test 1 : Fixed paacket size
#      Test 2 : Varying packet size (fixed per test)
        s1 = STLStream(name = 'stram1',
                       packet = packet,
                       flow_stats = STLFlowLatencyStats(pg_id = 5),
#                       flow_stats = STLFlowStats(pg_id = 5),
                       mode = STLTXCont(pps=pps)) 
#                        mode = STLTXSingleBurst(total_pkts = total_pkts,
#                                              pps = pps))    
	"""
	

#      Test 3 : Varying packet size (distribution)
        s1 = STLStream(name = 'stram1',
                       packet = packet,
                       flow_stats = STLFlowLatencyStats(pg_id = 5),
                       mode = STLTXCont(pps=pps*0.2))
#                       mode = STLTXMultiBurst(pps=200, pkts_per_burst =200, count = 50000))
#                      mode = STLTXSingleBurst(total_pkts = total_pkts,
#                                              pps = pps))

        print("S1: Length of the packet",len(pkt))

        pkt /= 'x' * 914
        packet = STLPktBuilder(pkt =pkt, vm= vm)
        s2 = STLStream(name = 'stream2',
                       packet = packet,
                       flow_stats = STLFlowLatencyStats(pg_id = 6),
                       mode = STLTXCont(pps=pps*0.6))
#                       mode = STLTXMultiBurst(pps=600, pkts_per_burst  = 600, count  = 50000))
#                      mode = STLTXSingleBurst(total_pkts = total_pkts,
#                                              pps = pps))
        print("S2: Length of the packet",len(pkt))


        pkt /= 'x' * 512
        packet = STLPktBuilder(pkt =pkt, vm= vm)
        s3 = STLStream(name = 'stream3',
                       packet = packet,
                       flow_stats = STLFlowLatencyStats(pg_id = 7),
                       mode = STLTXCont(pps=pps*0.2))
#                      mode = STLTXSingleBurst(total_pkts = total_pkts,
#                                              pps = pps))
        print("S3: Length of the packet",len(pkt))

	"""
#      Test 4 : Varying packet flow (distribution)
        vm = STLScVmRaw( [ STLVmFlowVar(name="ip_dst",
                           min_value="8.8.8.1",
                           max_value="8.8.8.10",
                         size=4, op="inc"), 
                           STLVmWrFlowVar(fv_name="ip_dst", pkt_offset= "IP:1.dst"),
                           STLVmFixIpv4(offset = "IP"),
                           )

        packet = STLPktBuilder(pkt =pkt, vm = vm)
        s4 = STLStream(name = 'stram4',
                       packet = packet,
                       flow_stats = STLFlowLatencyStats(pg_id =  9),
                       mode = STLTXCont(pps=pps))
#                      mode = STLTXSingleBurst(total_pkts = total_pkts,
#                                              pps = pps))
	"""

        # connect to server
        c.connect()
        # prepare our ports
        c.reset(ports = [tx_port, rx_port])
        # add streams to ports
#        c.add_streams([s1], ports = [tx_port])
        c.add_streams([s1, s2, s3], ports = [tx_port])
        print("\nInjecting packets \n")
        print("All strams: Length of the packet", packet.get_pkt_len())
        rc = rx_iteration(c, tx_port, rx_port, total_pkts, packet.get_pkt_len())
        if not rc:
            passed = False
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
#    f = open("output.txt", "a")
    tx_pps_list =  []
    rx_pps_list =  []
    throughput = 0

    c.clear_stats()
    c.start(ports = [tx_port])
    pgids = c.get_active_pgids()
    print ("Currently used pgids: {0}".format(pgids))
    for i in range(1,6):
        time.sleep(1)
        stats = c.get_pgid_stats(pgids['latency'])
        flow_stats = stats['flow_stats'].get(5)
        rx_pps = flow_stats['rx_pps'][rx_port]
        tx_pps = flow_stats['tx_pps'][tx_port]
        rx_bps = flow_stats['rx_bps'][rx_port]
        tx_bps = flow_stats['tx_bps'][tx_port]
        rx_bps_l1 = flow_stats['rx_bps_l1'][rx_port]
        tx_bps_l1 = flow_stats['tx_bps_l1'][tx_port]
        print("tx_pps:{0} rx_pps:{1}, rx_bps:{2}/{3} tx_bps:{4}/{5}"
              .format( tx_pps, rx_pps, rx_bps, rx_bps_l1, tx_bps, tx_bps_l1));
	tx_pps_list.append(tx_pps)
        rx_pps_list.append(rx_pps)

    throughput = Average(rx_pps_list)*110*8*0.000001
    print("tx_pps_avg:{0}, rx_pps_avg:{1}, Average throughput:{2} Mbps".format(Average(tx_pps_list), Average(rx_pps_list), round(throughput,4) ));
#    print("tx_pps_avg:{0}, rx_pps_avg:{1}".format(Average(tx_pps_list), Average(rx_pps_list))3
    c.wait_on_traffic(ports = [rx_port])
#    print("hello here")
    stats = c.get_pgid_stats(pgids['latency'])
    flow_stats = stats['flow_stats'].get(5)
    global_lat_stats = stats['latency']
    lat_stats = global_lat_stats.get(5)
    if not flow_stats:
        print("no flow stats available")
        return False
    if not lat_stats:
        print("no latency stats available")
        return False
    tx_pkts = flow_stats['tx_pkts'].get(tx_port, 0)
    tx_bytes = flow_stats['tx_bytes'].get(tx_port, 0)
    rx_pkts = flow_stats['rx_pkts'].get(rx_port, 0)
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


    lat_stats_s1 = global_lat_stats.get(5)      
    lat_s1=lat_stats_s1['latency']['average']    
    lat_stats_s2 = global_lat_stats.get(6) 
    lat_s2=lat_stats_s2['latency']['average']
    lat_stats_s3 = global_lat_stats.get(7) 
    lat_s3=lat_stats_s3['latency']['average']
 
    with open("/home/rohan/bench/bench_files/logs/latency/latency.csv", "a") as f:    
        rows   = [[lat_s1],[lat_s2],[lat_s3]] 
    	writer = csv.writer(f)
#        writer.writerow([avg])
        writer.writerow(rows)
        f.close()

    flow_stats_s1 = stats['flow_stats'].get(5)
    rx_pps_s1 = flow_stats_s1['rx_pps'][rx_port]
    tput_s1= round(rx_pps_s1*110*8*0.000001,4)
    flow_stats_s2 = stats['flow_stats'].get(6)
    rx_pps_s2 = flow_stats_s2['rx_pps'][rx_port]
    tput_s2= round(rx_pps_s2*1024*8*0.000001,4)
    flow_stats_s3 = stats['flow_stats'].get(7)
    rx_pps_s3 = flow_stats_s3['rx_pps'][rx_port]
    tput_s3= round(rx_pps_s3*1536*8*0.000001,4)


    with open("/home/rohan/bench/bench_files/logs/throughput/throughput.csv", "a") as f:
        rows   = [[tput_s1],[tput_s2],[tput_s3]]
        writer = csv.writer(f)
        fields = ['tx_pps_avg', 'rx_pps_avg']
#        rows   = [[Average(tx_pps_list)], [Average(rx_pps_list)], [throughput]]
#        rows   = [[throughput]]
#        writer.writerow(fields) 
        writer.writerow(rows)
#        writer.writerow([round(throughput,4)]) 
        f.close()

    if c.get_warnings():
            print("\n\n*** test had warnings ****\n\n")
            for w in c.get_warnings():
                print(w)
            return False
    print('Error counters: dropped:{0}, ooo:{1} dup:{2} seq too high:{3} seq too low:{4}'.format(drops, ooo, dup, sth, stl))
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
    return True

#Run test
i=0
packet_len = 1
while(i<51):
        print("Iteration :- ", i)
	rx_example(tx_port = 0, rx_port = 1, burst_size = 1000, pps = 1000, packet_len = 914)
        i+=1





                                                                                                                                                                   
