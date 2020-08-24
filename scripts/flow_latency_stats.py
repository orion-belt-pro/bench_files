from trex.stl.api import *
import time
import pprint
from scapy.contrib.gtp import *
from trex_stl_lib.api import *
import csv
log_path=""

# defalt PPS 400K, Pkt size 1024
########	Test1: var_pkt_size = Varying packet size (Fixed per test)
pkt_size = [100, 256, 512, 1024, 1280, 1536, 1790, 2000]
#pkt_size = [2000]

########	Test2: var_pps = Varying pps (Fixed per test)
pps = [1, 10, 100, 200, 400, 600, 800, 1000] # Kilo pps

########        Test3: var_pps_pkt_size_dist  = Varying pps (Distributed per test -> 20% low(100Byte), 60% medium(1024Byte), 20% high(1536Byte))
pps_dist = [1, 10, 100, 200, 400, 600, 800, 1000] # Kilo pps
pkt_size_dist = [100, 1024, 1536]
#pps = [10] # Kilo pps 
########	Test4: var_flow = Varying flow (Fixed per test)
flows = [10, 20, 30, 40, 50]

########	Test5: var_flow_dist = Varying flow
#flows = [10, 30, 50] # Flow distribution for pkt size 100, 1024 &nd 1536 respt.

########        Test5: LBO
#flows = [10, 30, 50] # Flow distribution for pkt size 100, 1024 &nd 1536 respt.

########       Direction = uplink or downlink

test="var_flow"
direction="uplink"

def run_test (tx_port, rx_port, pps, test, direction, var, dist):
    # create client
    c = STLClient()
    passed = True
    streams = []
    try:
        vm_src = STLScVmRaw([STLVmFlowVar(name="ip_src",
                           min_value="8.8.8.1",
                           max_value="8.8.8.10",
                         size=4, op="inc"),
                           STLVmWrFlowVar(fv_name="ip_src", pkt_offset= "IP.src"),
                           STLVmFixIpv4(offset = "IP"),
                           ])

	max_value="8.8.8.10"
	if test =="var_flow":
		max_value="8.8.8."+str(var)
	print"Value of max value",max_value
        vm_dst = STLScVmRaw([STLVmFlowVar(name="ip_dst",
                           min_value="8.8.8.1",
                           max_value=max_value,
                         size=4, op="inc"),
                           STLVmWrFlowVar(fv_name="ip_dst", pkt_offset= "IP:1.dst"),
                           STLVmFixIpv4(offset = "IP:1"),
                           ])

        if direction == "uplink":
		print("Uplink test")
#		uplink gtp packet
#        	pkt = Ether()/IP(src="172.20.16.99",dst="172.20.16.105")/UDP(dport=2152)/GTP_U_Header(teid=1234)/IP(src="10.10.10.10",dst="172.20.16.55",version=4,id=0xFFFF)/UDP()/'at_least_16_bytes_payload_needed'
        	pkt = Ether()/IP(src="172.20.16.99",dst="172.20.16.105")/UDP(dport=2152)/GTP_U_Header(teid=1234)/IP(src="10.10.10.10",version=4,id=0xFFFF)/UDP()/'at_least_16_bytes_payload_needed'
                vm = vm_dst
		log_path="ul"
	else:
                print("Downlink test") 
#       	downlink packet 
#        	pkt = Ether()/IP(src="172.20.16.55",dst="10.10.10.10",version=4,id=0xFFFF)/UDP()/'at_least_16_bytes_payload_needed'
                pkt = Ether()/IP(dst="10.10.10.10",version=4,id=0xFFFF)/UDP()/'at_least_16_bytes_payload_needed'
		vm = vm_src
		log_path ="dl"
		pkt /= 'x' * 36 # This padding is done to make uplink and downlink packet of same size for comparison (TBD)
        print("Length of the packet",len(pkt))

##############################################
	if test == "var_pkt_size":
		pkt /= 'x' * (var-len(pkt))
		print("Length of the packet after padding",len(pkt))
		packet = STLPktBuilder(pkt =pkt, vm = vm)
		print "##### Test 1 : Varying packet size (fixed per test)#####"
        	s1 = STLStream(name = 'stram1',
                		packet = packet,
                       		flow_stats = STLFlowLatencyStats(pg_id = 5),
                       		mode = STLTXCont(pps=pps))
                streams = [s1]

##############################################
	if test == "var_pps_pkt_size_dist":
        	print "##### Test 3 : Varying packet size (distribution)#####"
		pkt /= 'x' * (dist[0]-len(pkt))  # 100 Byte
		packet = STLPktBuilder(pkt =pkt, vm = vm)
        	s1 = STLStream(name = 'stram1',
                       		packet = packet,
                       		flow_stats = STLFlowLatencyStats(pg_id=5),
                       		mode = STLTXCont(pps=var*0.2*1000))
                print("Stream1: Length of the packet",len(pkt))

        	pkt /= 'x' * (dist[1]-len(pkt))  # 1024 Byte
        	packet = STLPktBuilder(pkt =pkt, vm= vm)
        	s2 = STLStream(name = 'stream2',
                       		packet = packet,
                       		flow_stats = STLFlowLatencyStats(pg_id = 6),
                       		mode = STLTXCont(pps=var*0.6*1000))
        	print("Stream2: Length of the packet",len(pkt))

        	pkt /= 'x' * (dist[2]-len(pkt))  # 1536 Byte
        	packet = STLPktBuilder(pkt =pkt, vm= vm)
        	s3 = STLStream(name = 'stream3',
                       		packet = packet,
                       		flow_stats = STLFlowLatencyStats(pg_id = 7),
                       		mode = STLTXCont(pps=var*0.2*1000))
        	print("S3: Length of the packet",len(pkt))
		print("pps", var*0.2*1000, var*0.6*1000)
	        streams = [s1, s2, s3]

##############################################
        if test == "var_pps":
		pkt /= 'x' * 914
		print("Length of the packet after padding",len(pkt))
		packet = STLPktBuilder(pkt =pkt, vm = vm)
		print "#####  Test3 = Varying pps (Fixed per test)#####"
                s1 = STLStream(name = 'stram1',
                                packet = packet,
                                flow_stats = STLFlowLatencyStats(pg_id = 5),
				mode = STLTXCont(pps=var*1000))
                streams = [s1]

##############################################
	if test == "var_flow":
	        print "Number of flows", var
#		cont = raw_input("Continue : yes/no  ? (Make sure number of PFCP sessions)") 
#		if cont == "yes":
		pkt /= 'x' * 914
		print("Length of the packet after padding",len(pkt))
		print "#####  Test3 = Varying flow (Fixed per test)#####"
		packet = STLPktBuilder(pkt =pkt, vm = vm)
                s4 = STLStream(name = 'stram4',
                               packet = packet,
                               flow_stats = STLFlowLatencyStats(pg_id =  5),
                               mode = STLTXCont(pps=pps))
		streams = [s4]
##############################################

        # connect to server
        c.connect()
        # prepare our ports
        c.reset(ports = [tx_port, rx_port])
        # add streams to ports
        print("\nInjecting packets \n")
        c.add_streams(streams, ports = [tx_port])
        print("All strams: Length of the packet", packet.get_pkt_len())
	rc = get_stats(c, tx_port, rx_port, packet.get_pkt_len(), test, var, log_path)
	"""
	i=0
	while(i<4):
		rc = rx_iteration(c, tx_port, rx_port, packet.get_pkt_len())
        	if not rc:
            		passed = False
		i+=1
	"""
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
def get_stats (c, tx_port, rx_port, pkt_len, test, var, path):
    c.clear_stats()
    c.start(ports = [tx_port])
#    time.sleep(5)
    pgids = c.get_active_pgids()
    print ("Currently used pgids: {0}".format(pgids))

    rx_bps_tot_s1 = []
    rx_bps_tot_s2 = []
    rx_bps_tot_s3 = []
    for i in range(1,6):
        time.sleep(1)
        stats = c.get_pgid_stats(pgids['latency'])
        flow_stats = stats['flow_stats'].get(5)
        rx_pps = flow_stats['rx_pps'][rx_port]
        tx_pps = flow_stats['tx_pps'][tx_port]
        rx_bps = flow_stats['rx_bps'][rx_port]
        tx_bps = flow_stats['tx_bps'][tx_port]
        rx_bps_tot_s1.append(rx_bps)
        print("rx_pps:{0} tx_pps:{1}, rx_bps:{2}, tx_bps:{3}"
              .format(rx_pps, tx_pps, rx_bps, tx_bps));
        if test == "var_pps_pkt_size_dist":
		 flow_stats_s2 = stats['flow_stats'].get(6)
		 flow_stats_s3 = stats['flow_stats'].get(7)
		 rx_bps_s2 = flow_stats_s2['rx_bps'][rx_port]
		 rx_bps_s3 = flow_stats_s3['rx_bps'][rx_port]
		 rx_bps_tot_s2.append(rx_bps_s2)
		 rx_bps_tot_s3.append(rx_bps_s3)

    rx_bps_avg_s1 = Average(rx_bps_tot_s1)*0.000001
    print"Avg Throughput= ",rx_bps_avg_s1 ," Mbps"

    stats = c.get_pgid_stats(pgids['latency'])
    global_lat_stats = stats['latency']

    drops = global_lat_stats.get(5)['err_cntrs']['dropped']
    print"dropped packets ",drops

#    c.wait_on_traffic(ports = [rx_port])

    with open("/home/rohan/bench/bench_files/logs/throughput/"+path+"/"+test+"_"+str(var)+".csv", "a") as f:
    	writer = csv.writer(f)
        if test == "var_pps_pkt_size_dist":
		rx_bps_avg_s2 = Average(rx_bps_tot_s2)*0.000001
		rx_bps_avg_s3 = Average(rx_bps_tot_s3)*0.000001
                rows  = [rx_bps_avg_s1, rx_bps_avg_s2, rx_bps_avg_s3]
		writer.writerow(rows)
	else:
        	writer.writerow([rx_bps_avg_s1])
        f.close()
   
    if c.get_warnings():
            print("\n\n*** test had warnings ****\n\n")
            for w in c.get_warnings():
                print(w)
            return False
    return True

#Run test
packet_len = 1

if test=="var_pkt_size":
	for index in pkt_size:
		print "Test for packet size :", index,"Bytes"
		number_of_tests=0
		while(number_of_tests < 25):
			run_test(tx_port = 0, rx_port = 1, pps = 400000, test = test, direction = direction, var = index, dist = 0)
			number_of_tests+=1

if test=="var_pps_pkt_size_dist":
        for index in pps_dist:
                print "Test for varying pps (pkt size dist) :", index,"K"
         	number_of_tests=0
         	while(number_of_tests < 25):
                	run_test(tx_port = 0, rx_port = 1, pps = 400000, test = test, direction = direction, var = index, dist = pkt_size_dist)
                	number_of_tests+=1

if test=="var_pps":
        for index in pps:
                print "Test for varying pps :", index,"K"
                number_of_tests=0
                while(number_of_tests < 25):
                        run_test(tx_port = 0, rx_port = 1, pps = 1, test = test, direction = direction, var = index, dist = 0)
                        number_of_tests+=1

if test=="var_flow":
        for index in flows:
                print "Test for varying flows :", index
		cont = raw_input("Continue : yes/no  ? (Make sure number of PFCP sessions) ")
                if direction == "uplink":
                        pps = 600000 # 4.91 Gbps max tput
                if direction == "downlink":
                        pps = 750000 # 6.14 Gbps max tput
		if cont == "yes":
                	number_of_tests=0
                	while(number_of_tests < 25):
                        	run_test(tx_port = 0, rx_port = 1, pps = pps, test = test, direction = direction, var = index, dist = 0)
                        	number_of_tests+=1
