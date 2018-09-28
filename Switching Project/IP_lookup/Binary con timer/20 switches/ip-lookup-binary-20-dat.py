# IMPORT LIBRARIES
import json
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath
#aggiunte
from collections import deque 
from datetime import datetime


# REST API for switch configuration
#
# get switches
# GET /v1.0/lookup/switches
#
# get bridge-table
# GET /v1.0/lookup/bridge-table
#
# get lookup
# GET /v1.0/lookup/lookup
#
# get ip-to-mac
# GET /v1.0/lookup/ip-to-mac

IP     = 0
SUBNET = 1
MAC    = 2
NAME   = 3
DPID   = 4
###################################################################################################################################
length=0
last_prefix=None
###################################################################################################################################
#funzione di conversione da binario a IP
def fromBinarytoIP(string):
	splitter = 8
	divided = [string[i:i+splitter] for i in range(0, len(string), splitter)]
	decimal = []
	i = 0
	while i < 4:
		decimal.append(int(divided[i], 2))
		i = i + 1
	IPaddress = str(decimal[0])
	for i in range(1,4):
		IPaddress = IPaddress +'.'+ str(decimal[i])
	return str(IPaddress)

#funzione di conversione da IP a numero binario
def fromIPtoBinary(string):
	w1, w2, w3, w4 = string.split(".")
	binaryN = [ str(bin(int(w1)))[2:], str(bin(int(w2)))[2:], str(bin(int(w3)))[2:], str(bin(int(w4)))[2:]]
	binaryN = paddingAddress(binaryN)
	addressIP = binaryN[0]
	i=1
	while i<4:
		addressIP = addressIP+binaryN[i]
		i=i+1
	return str(addressIP)

#funzione per portare i vari numeri dell'indirizzo IP a binari a 8 cifre
def paddingAddress(list):
	i = 0
	padded_list = list;
	while i < len(list):
		if len(list)<8:
			while len(padded_list[i]) < 8:
				padded_list[i] = '0' + padded_list[i]
		i = i + 1
	return padded_list

#classe nodo dell'albero binario
class Node():

	#initialization of a node for the tree
	def __init__(self,key):
		self.key = key
		self.left = None
		self.right = None
		self.parent = None
		self.gateway = None
	
	#adding a gateway address to the tree
	def add_gw(self, gateway):
		self.gateway = gateway;

#classe rappresentante l'albero binario
class Tree():
        
        #initialization of the tree setting the root to None
        def __init__(self):
		self.root = None
	
	#building the tree appending one node
	def add_node(self,key,node=None):
                global length
                #setting the root
		if node is None:
			node = self.root
		
		
		
		if self.root is None:
			self.root = Node(key)
		else: 
                        if (key[length]=='0'):
                                length=length+1 
				#adding left node      
				if node.left is None:
					node.left = Node(key)
					node.left.parent = node
                                        length=0
					return 
				else:
					#adding nodes to the left one
					return self.add_node(key,node = node.left)
			else:
                                length=length+1
				#adding right node
				if node.right is None:
					node.right = Node(key)
					node.right.parent = node
                                        length=0
					return 
				else:
					#adding nodes to the right one 
					return self.add_node(key,node = node.right)
	
	#searching a specific node to assign him a gw		
	def add_gw(self,key, l, gateway, node):
                #print "gateway: ", gateway,"\tIndice: ",l,"\tkey: ",key
                #print "Lunghezza maschera: ", len(key)
		if node is None:
			node = self.root
                
		if self.root.key == key:
			node.add_gw(gateway)
			print "Gateway added to the root: ", node.gateway
			l = 0;
			return 
		else:
                        #print "Lunghezza chiave nodo: ", len(node.key), "\t Chiave: ",key, "Primi char: ", node.key[0:(l)]
			if len(node.key) == len(key) and node.key[0:(l)] == key:
				print "Gateway added to node: ", node.key, " - IP: ", gateway
				node.add_gw(gateway)
				l = 0
				return
			
			elif l<len(key) and key[l] == "0" and node.left is not None:
				l = l + 1
				return self.add_gw(key, l, gateway, node = node.left)

			elif l<len(key) and key[l] == "1" and node.right is not None:
				l = l + 1
				return self.add_gw(key, l, gateway, node = node.right)
			else:
				l = 0;
				return None
	
	#print of the tree with nodes ordered by level	
	def print_tree(self, head, queue=deque()):
		if head is None:
       			return
    		print "\nkey: ", fromBinarytoIP(head.key), "\nGw: ", head.gateway
		if head.right is not None:
			print "Node dx: ", fromBinarytoIP(head.right.key)
		else:	print "Node dx:  --"
		if head.left is not None:
			print "Node sx: ", fromBinarytoIP(head.left.key)
		else:	print "Node sx:  --"
    		[queue.append(node) for node in [head.left, head.right] if node]
    		if queue:
        		self.print_tree(queue.popleft(), queue)
		
	#function to find the destination for a certain address as input	
	def finding_prefix(self, IP_add_str, n1, i):
		global last_prefix
		IP_add_bin = fromIPtoBinary(IP_add_str);
		#IP_add_bin = IP_add_str;		
	
		if last_prefix == '*':
			#default address
			return "*";
		
		#indice di ricerca < della lunghezza dell'indirizzo binario
		if i<len(IP_add_bin):
			
			#carattere successivo dell'IP e' uno zero e nodo attuale ha un figlio
			if IP_add_bin[i] == "0" and n1.left is not None:
				i = i +1;
				if n1.gateway is not None:
					last_prefix = n1.gateway;
				return self.finding_prefix(IP_add_str, n1.left, i);
	
			#carattere successivo dell'IP e' un uno e nodo attuale ha un figlio
			elif IP_add_bin[i] == "1" and n1.right is not None:
				i = i +1;
				if n1.gateway is not None:
					last_prefix = n1.gateway;
				return self.finding_prefix(IP_add_str, n1.right, i);
			
			#se arrivo qui, non ho figli, sono in fondo all'albero	
			else:
				if n1.gateway is not None:
					print "Ricerca finita: io sono il gw\n"
					return n1.gateway;
				else:
					return last_prefix;
		else:
			#nessun matching finale, ritorno al prefisso salvato
			print "\nRicerca finita: nessun matching finale trovato, ultimo prefisso: ", last_prefix
			return last_prefix;

##################################
t = Tree();
t.add_node("*")
file_nodes = open("/home/user/Downloads/ryu/ryu/app/nodi.dat","r")

while 1:
        chiave = file_nodes.readline()
        if chiave == "":
                break
        if chiave[0] == '#':
                continue
        chiave = chiave[0:len(chiave)-2]
        #print "-- Chiave: ", chiave
	t.add_node(chiave)
	#print "-- Chiave aggiunta!"
	

file_nodes.close()


#t.add_gw("100001111011", 0, "135.176.0.254", None);
#t.add_gw("1000011110110100", 0, "135.180.0.254", None);
#t.add_gw("111100111110101000101011", 0, "243.234.43.0", None);
t.add_gw("00001011",0, "11.0.0.254", None);
t.add_gw("00100000",0, "32.0.0.254", None);
t.add_gw("00101100",0, "44.0.0.254", None);
t.add_gw("00111110",0, "62.0.0.254", None);
t.add_gw("01000001",0, "65.0.0.254", None);
t.add_gw("01111000",0, "120.0.0.254", None);
t.add_gw("10000101",0, "133.0.0.254", None);
t.add_gw("10011110",0, "158.0.0.254", None);
t.add_gw("10111000",0, "184.0.0.254", None);
t.add_gw("11000011", 0, "195.0.0.254", None);
t.add_gw("000010101100",0, "10.192.0.254", None);
t.add_gw("001000010110",0, "33.96.0.254", None);
t.add_gw("001100101010",0, "50.160.0.254", None);
t.add_gw("010000010011",0, "65.48.0.254", None);
t.add_gw("100001001000",0, "132.128.0.254", None);
t.add_gw("100001111011",0, "135.176.0.254", None);
t.add_gw("100111101000",0, "158.128.0.254", None);
t.add_gw("101110010101",0, "185.80.0.254", None);
t.add_gw("101110000010",0, "184.32.0.254", None);
t.add_gw("011101110010",0, "119.32.0.254", None);


##################################################################################################################################


# Main class for switch
class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    # Initialize the application 
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(LookupController, {'lookup_api_app': self})

        # Add all initialization code here
        self.mac_to_port = {} 
        self.mac_to_port["1"] = {}
        self.mac_to_port["2"] = {}
        self.mac_to_port["3"] = {}
        self.mac_to_port["4"] = {}
        self.mac_to_port["5"] = {}
        self.mac_to_port["6"] = {}
        self.mac_to_port["7"] = {}
        self.mac_to_port["8"] = {}
        self.mac_to_port["9"] = {}
        self.mac_to_port["10"] = {}
        self.mac_to_port["11"] = {}
        self.mac_to_port["12"] = {}
        self.mac_to_port["13"] = {}
        self.mac_to_port["14"] = {}
        self.mac_to_port["15"] = {}
        self.mac_to_port["16"] = {}
        self.mac_to_port["17"] = {}
        self.mac_to_port["18"] = {}
        self.mac_to_port["19"] = {}
        self.mac_to_port["20"] = {}


        self.mac_to_port["1"]["00:00:00:00:00:01"] = 1
        self.mac_to_port["1"]["00:00:00:00:00:02"] = 2
        self.mac_to_port["2"]["00:00:00:00:00:03"] = 1
        self.mac_to_port["2"]["00:00:00:00:00:04"] = 2
        self.mac_to_port["3"]["00:00:00:00:00:05"] = 1
        self.mac_to_port["3"]["00:00:00:00:00:06"] = 2
        self.mac_to_port["3"]["00:00:00:00:00:07"] = 3
        self.mac_to_port["4"]["00:00:00:00:00:08"] = 1
        self.mac_to_port["4"]["00:00:00:00:00:09"] = 2
        self.mac_to_port["4"]["00:00:00:00:00:0a"] = 3
        self.mac_to_port["5"]["00:00:00:00:00:0b"] = 1
        self.mac_to_port["5"]["00:00:00:00:00:0c"] = 2
        self.mac_to_port["6"]["00:00:00:00:00:0d"] = 1
        self.mac_to_port["6"]["00:00:00:00:00:0e"] = 2
        self.mac_to_port["7"]["00:00:00:00:00:0f"] = 1
        self.mac_to_port["7"]["00:00:00:00:00:10"] = 2
        self.mac_to_port["8"]["00:00:00:00:00:11"] = 1
        self.mac_to_port["8"]["00:00:00:00:00:12"] = 2
        self.mac_to_port["8"]["00:00:00:00:00:13"] = 3
        self.mac_to_port["9"]["00:00:00:00:00:14"] = 1
        self.mac_to_port["9"]["00:00:00:00:00:15"] = 2
        self.mac_to_port["10"]["00:00:00:00:00:16"] = 1
        self.mac_to_port["10"]["00:00:00:00:00:17"] = 2
        self.mac_to_port["10"]["00:00:00:00:00:18"] = 3
        self.mac_to_port["10"]["00:00:00:00:00:19"] = 4
        self.mac_to_port["11"]["00:00:00:00:00:1a"] = 1
        self.mac_to_port["11"]["00:00:00:00:00:1b"] = 2
        self.mac_to_port["12"]["00:00:00:00:00:1c"] = 1
        self.mac_to_port["12"]["00:00:00:00:00:1d"] = 2
        self.mac_to_port["12"]["00:00:00:00:00:1e"] = 3
        self.mac_to_port["13"]["00:00:00:00:00:1f"] = 1
        self.mac_to_port["13"]["00:00:00:00:00:20"] = 2
        self.mac_to_port["14"]["00:00:00:00:00:21"] = 1
        self.mac_to_port["14"]["00:00:00:00:00:22"] = 2
        self.mac_to_port["15"]["00:00:00:00:00:23"] = 1
        self.mac_to_port["15"]["00:00:00:00:00:24"] = 2
        self.mac_to_port["16"]["00:00:00:00:00:25"] = 1
        self.mac_to_port["16"]["00:00:00:00:00:26"] = 2
        self.mac_to_port["16"]["00:00:00:00:00:27"] = 3
        self.mac_to_port["17"]["00:00:00:00:00:28"] = 1
        self.mac_to_port["17"]["00:00:00:00:00:29"] = 2
        self.mac_to_port["17"]["00:00:00:00:00:2a"] = 3
        self.mac_to_port["17"]["00:00:00:00:00:2b"] = 4
        self.mac_to_port["18"]["00:00:00:00:00:2c"] = 1
        self.mac_to_port["18"]["00:00:00:00:00:2d"] = 2
        self.mac_to_port["19"]["00:00:00:00:00:2e"] = 1
        self.mac_to_port["19"]["00:00:00:00:00:2f"] = 2
        self.mac_to_port["20"]["00:00:00:00:00:30"] = 1
        self.mac_to_port["20"]["00:00:00:00:00:31"] = 2
        self.mac_to_port["20"]["00:00:00:00:00:32"] = 3


        self.switch = {}
        self.switch["11.0.0.254"  ] = ["11.0.0.254","8" ,"00:00:00:11:11:01","s1","1"]
        self.switch["32.0.0.254"] = ["32.0.0.254","8","00:00:00:11:11:02","s2","2"]
        self.switch["44.0.0.254"] = ["44.0.0.254","8","00:00:00:11:11:03","s3","3"]
        self.switch["62.0.0.254"] = ["62.0.0.254","8","00:00:00:11:11:04","s4","4"]
        self.switch["65.0.0.254"] = ["65.0.0.254", "8", "00:00:00:11:11:05", "s5", "5"]
        self.switch["120.0.0.254"] = ["120.0.0.254", "8", "00:00:00:11:11:06", "s6", "6"]
        self.switch["133.0.0.254"] = ["133.0.0.254", "8", "00:00:00:11:11:07", "s7", "7"]
        self.switch["158.0.0.254"] = ["158.0.0.254", "8", "00:00:00:11:11:08", "s8", "8"]
        self.switch["184.0.0.254"] = ["184.0.0.254", "8", "00:00:00:11:11:09", "s9", "9"]
        self.switch["195.0.0.254"] = ["195.0.0.254", "8", "00:00:00:11:11:0a", "s10", "10"]
        self.switch["10.192.0.254"] = ["10.192.0.254", "12", "00:00:00:11:11:0b", "s11", "11"]
        self.switch["33.96.0.254"] = ["33.96.0.254", "12", "00:00:00:11:11:0c", "s12", "12"]
        self.switch["50.160.0.254"] = ["50.160.0.254", "12", "00:00:00:11:11:0d", "s13", "13"]
        self.switch["65.48.0.254"] = ["65.48.0.254", "12", "00:00:00:11:11:0e", "s14", "14"]
        self.switch["132.128.0.254"] = ["132.128.0.254", "12", "00:00:00:11:11:0f", "s15", "15"]
        self.switch["135.176.0.254"] = ["135.176.0.254", "12", "00:00:00:11:11:10", "s16", "16"]
        self.switch["158.128.0.254"] = ["158.128.0.254", "12", "00:00:00:11:11:11", "s17", "17"]
        self.switch["185.80.0.254"] = ["185.80.0.254", "12", "00:00:00:11:11:12", "s18", "18"]
        self.switch["184.32.0.254"] = ["184.32.0.254", "12", "00:00:00:11:11:13", "s19", "19"]
        self.switch["119.32.0.254"] = ["119.32.0.254", "12", "00:00:00:11:11:14", "s20", "20"]

        # self.lookup = {}
        # self.lookup["195.0.0.1"]   = "195.0.0.254"
        # self.lookup["195.0.0.2"]   = "195.0.0.254"
        # self.lookup["135.176.0.1"] = "135.176.0.254"
        # self.lookup["135.176.0.2"] = "135.176.0.254"
        # self.lookup["135.180.0.1"] = "135.180.0.254"
        # self.lookup["135.180.0.2"] = "135.180.0.254"
        # self.lookup["243.234.43.1"] = "243.234.43.254"
        # self.lookup["243.234.43.2"] = "243.234.43.254"

        self.ip_to_mac = {}
        self.ip_to_mac["11.0.0.1"] = "00:00:00:00:00:01"
        self.ip_to_mac["11.0.0.2"] = "00:00:00:00:00:02"
        self.ip_to_mac["32.0.0.1"] = "00:00:00:00:00:03"
        self.ip_to_mac["32.0.0.2"] = "00:00:00:00:00:04"
        self.ip_to_mac["44.0.0.1"] = "00:00:00:00:00:05"
        self.ip_to_mac["44.0.0.2"] = "00:00:00:00:00:06"
        self.ip_to_mac["44.0.0.3"] = "00:00:00:00:00:07"
        self.ip_to_mac["62.0.0.1"] = "00:00:00:00:00:08"
        self.ip_to_mac["62.0.0.2"] = "00:00:00:00:00:09"
        self.ip_to_mac["62.0.0.3"] = "00:00:00:00:00:0a"
        self.ip_to_mac["65.0.0.1"] = "00:00:00:00:00:0b"
        self.ip_to_mac["65.0.0.2"] = "00:00:00:00:00:0c"
        self.ip_to_mac["120.0.0.1"] = "00:00:00:00:00:0d"
        self.ip_to_mac["120.0.0.2"] = "00:00:00:00:00:0e"
        self.ip_to_mac["133.0.0.1"] = "00:00:00:00:00:0f"
        self.ip_to_mac["133.0.0.2"] = "00:00:00:00:00:10"
        self.ip_to_mac["158.0.0.1"] = "00:00:00:00:00:11"
        self.ip_to_mac["158.0.0.2"] = "00:00:00:00:00:12"
        self.ip_to_mac["158.0.0.3"] = "00:00:00:00:00:13"
        self.ip_to_mac["184.0.0.1"] = "00:00:00:00:00:14"
        self.ip_to_mac["184.0.0.2"] = "00:00:00:00:00:15"
        self.ip_to_mac["195.0.0.1"] = "00:00:00:00:00:16"
        self.ip_to_mac["195.0.0.2"] = "00:00:00:00:00:17"
        self.ip_to_mac["195.0.0.3"] = "00:00:00:00:00:18"
        self.ip_to_mac["195.0.0.4"] = "00:00:00:00:00:19"
        self.ip_to_mac["10.192.0.1"] = "00:00:00:00:00:1a"
        self.ip_to_mac["10.192.0.2"] = "00:00:00:00:00:1b"
        self.ip_to_mac["33.96.0.1"] = "00:00:00:00:00:1c"
        self.ip_to_mac["33.96.0.2"] = "00:00:00:00:00:1d"
        self.ip_to_mac["33.96.0.3"] = "00:00:00:00:00:1e"
        self.ip_to_mac["50.160.0.1"] = "00:00:00:00:00:1f"
        self.ip_to_mac["50.160.0.2"] = "00:00:00:00:00:20"
        self.ip_to_mac["65.48.0.1"] = "00:00:00:00:00:21"
        self.ip_to_mac["65.48.0.2"] = "00:00:00:00:00:22"
        self.ip_to_mac["132.128.0.1"] = "00:00:00:00:00:23"
        self.ip_to_mac["132.128.0.2"] = "00:00:00:00:00:24"
        self.ip_to_mac["135.176.0.1"] = "00:00:00:00:00:25"
        self.ip_to_mac["135.176.0.2"] = "00:00:00:00:00:26"
        self.ip_to_mac["135.176.0.3"] = "00:00:00:00:00:27"
        self.ip_to_mac["158.128.0.1"] = "00:00:00:00:00:28"
        self.ip_to_mac["158.128.0.2"] = "00:00:00:00:00:29"
        self.ip_to_mac["158.128.0.3"] = "00:00:00:00:00:2a"
        self.ip_to_mac["158.128.0.4"] = "00:00:00:00:00:2b"
        self.ip_to_mac["185.80.0.1"] = "00:00:00:00:00:2c"
        self.ip_to_mac["185.80.0.2"] = "00:00:00:00:00:2d"
        self.ip_to_mac["184.32.0.1"] = "00:00:00:00:00:2e"
        self.ip_to_mac["184.32.0.2"] = "00:00:00:00:00:2f"
        self.ip_to_mac["119.32.0.1"] = "00:00:00:00:00:30"
        self.ip_to_mac["119.32.0.2"] = "00:00:00:00:00:31"
        self.ip_to_mac["119.32.0.3"] = "00:00:00:00:00:32"

    def send_arp_reply(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort):
        e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, 2, srcMac, srcIp, dstMac, dstIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

  
          
    # Register PACKET HANDLER
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg                          # OpenFlow event message
        datapath = msg.datapath               # Switch class that received the packet   
        ofproto = datapath.ofproto            # OpenFlow protocol class  

        # Parse packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore lldp packet
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        
        src = eth.src
        dpid = datapath.id

        self.logger.info("--Packet IN: Switch id[%s], Src MAC[%s], Dst MAC[%s], Port[%s]", dpid, src, dst, msg.in_port)
        action = "allow"

        if dst == 'ff:ff:ff:ff:ff:ff': 
            self.logger.info("  Broadcast packet")
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                arp_packet = pkt.get_protocol(arp.arp)
                if arp_packet.opcode == 1:
                    arp_dst_ip = arp_packet.dst_ip
                    arp_src_ip = arp_packet.src_ip
                    self.logger.info("  Received ARP request for dst IP %s" % arp_dst_ip)
                    if arp_dst_ip in self.switch:
                        switch_mac = self.switch[arp_dst_ip][MAC]

                        self.send_arp_reply(datapath,switch_mac,arp_packet.dst_ip,src,arp_src_ip,msg.in_port) 
                        self.logger.info("  Sent gratious ARP reply [%s]-[%s] to %s " % 
                                         (arp_packet.dst_ip,switch_mac,arp_packet.src_ip))  

                        return 0


            actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:   #packet is not buffered on switch
                data = msg.data

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            self.logger.info("  Flooding packet to all other ports")
            datapath.send_msg(out)
            return


        ip4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip4_pkt:
            self.logger.info("  --- IP LOOKUP")
            src_ip = ip4_pkt.src
            dst_ip = ip4_pkt.dst
            self.logger.info("  --- src_ip[%s], dst_ip[%s]" % (src_ip,dst_ip))
           
            sw = None
	    t1 = datetime.now()
            sw = t.finding_prefix(dst_ip,t.root,0)
	    t2 = datetime.now()
	    self.logger.info('\n##########Duration: {}'.format(t2 - t1))
	    self.logger.info('\n');
	    if sw is not None:
            #if dst_ip in self.lookup:
                #sw = self.lookup[dst_ip]
                
                self.logger.info("  --- Destination present on switch %s" % (self.switch[sw]))
                dp = get_datapath(self,int(self.switch[sw][DPID]))
                #self.logger.info("----- Dest mac: %s" % self.ip_to_mac[dst_ip]); 
                out_port = self.mac_to_port[self.switch[sw][DPID]][self.ip_to_mac[dst_ip]] 
                self.logger.info("  --- Output port set to %s" % (out_port))

                actions = [dp.ofproto_parser.OFPActionOutput(int(out_port))]

                data = msg.data
                pkt = packet.Packet(data)
                eth = pkt.get_protocol(ethernet.ethernet)
                #change the mac address of packet
                eth.dst = self.ip_to_mac[dst_ip] 
                self.logger.info("  --- Changing destination mac to %s" % (eth.dst))

                pkt.serialize()
                out = dp.ofproto_parser.OFPPacketOut(
                    datapath=dp, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
                    actions=actions, data=pkt.data)
                print("---------")
                dp.send_msg(out)
                return





        # Forward the packet 
        if dst in self.mac_to_port[str(dpid)]:
            out_port = self.mac_to_port[str(dpid)][dst]
            self.logger.info("  Destination MAC is on port %s. Forwarding the packet", out_port)
        else:
            out_port =  ofproto.OFPP_FLOOD
            self.logger.info("  Destination MAC not present in table. Flood the packet")

        actions = [datapath.ofproto_parser.OFPActionOutput(int(out_port))]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

class LookupController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(LookupController, self).__init__(req, link, data, **config)
        self.lookup_api_app = data['lookup_api_app']

    @route('lookup', '/v1.0/lookup/lookup',
           methods=['GET'])
    def list_lookup(self, req, **kwargs):
        lookup_table = self.lookup_api_app.lookup
        body = json.dumps(lookup_table, sort_keys=True)
        return Response(content_type='application/json', body=body)

    
    @route('lookup', '/v1.0/lookup/switches',
           methods=['GET'])
    def list_switch(self, req, **kwargs):
        switch_table = self.lookup_api_app.switch
        body = json.dumps(switch_table, sort_keys=True)
        return Response(content_type='application/json', body=body)


    @route('lookup', '/v1.0/lookup/bridge-table',
           methods=['GET'])
    def list_bridge_table(self, req, **kwargs):
        bridge_table = self.lookup_api_app.mac_to_port
        body = json.dumps(bridge_table, sort_keys=True)
        return Response(content_type='application/json', body=body)

    @route('lookup', '/v1.0/lookup/ip-to-mac',
           methods=['GET'])
    def list_ip_to_mac_table(self, req, **kwargs):
        ip_to_mac_table = self.lookup_api_app.ip_to_mac
        body = json.dumps(ip_to_mac_table, sort_keys=True)
        return Response(content_type='application/json', body=body)


