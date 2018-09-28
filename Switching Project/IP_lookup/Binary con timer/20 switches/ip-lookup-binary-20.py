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
t.add_node("0")
t.add_node("00")
t.add_node("000")
t.add_node("0000")
t.add_node("00000")
t.add_node("00001")
t.add_node("000010")
t.add_node("000011")
t.add_node("0000100")
t.add_node("0000101")
t.add_node("00001010")
t.add_node("00001011")
t.add_node("000010100")
t.add_node("000010101")
t.add_node("0000101010")
t.add_node("0000101011")
t.add_node("00001010110")
t.add_node("00001010111")
t.add_node("000010101100")
t.add_node("0000101011000")
t.add_node("0000101011001")
t.add_node("00001010110010")
t.add_node("00001010110011")
t.add_node("000010101100111")
t.add_node("0000101011001110")
t.add_node("00001010110011101")
t.add_node("0000010101111")
t.add_node("0000101011110")
t.add_node("0000101011111")
t.add_node("00001010111110")
t.add_node("00001010111111")
t.add_node("000010101111110")
t.add_node("0000101011111101")
t.add_node("00001010111111010")
t.add_node("000010101111110100")
t.add_node("0000101011111101000")
t.add_node("0000101011111101001")
t.add_node("00001010111111011")
t.add_node("000010101111110111")
t.add_node("001")
t.add_node("0010")
t.add_node("00100")
t.add_node("001000")
t.add_node("0010000")
t.add_node("00100000")
t.add_node("00100001")
t.add_node("001000010")
t.add_node("0010000100")
t.add_node("0010000101")
t.add_node("00100001010")
t.add_node("00100001011")
t.add_node("001000010110")
t.add_node("001000010111")
t.add_node("0010000101110")
t.add_node("00100001011100")
t.add_node("001001")
t.add_node("0010011")
t.add_node("00101")
t.add_node("001011")
t.add_node("0010110")
t.add_node("00101100")
t.add_node("00101101")
t.add_node("001011010")
t.add_node("0010110100")
t.add_node("0010110101")
t.add_node("00101101010")
t.add_node("001011010100")
t.add_node("001011010101")
t.add_node("0010110101011")
t.add_node("00101101010110")
t.add_node("001011010101100")
t.add_node("001011010101101")
t.add_node("0010110101011000")
t.add_node("00101101010110001")
t.add_node("001011010101100011")
t.add_node("0010110101011000111")
t.add_node("00101101010110001111")
t.add_node("001011010101100011110")
t.add_node("0010110101011000111101")
t.add_node("00101101010110001111010")
t.add_node("001011010101100011110101")
t.add_node("0011")
t.add_node("00110")
t.add_node("001100")
t.add_node("0011000")
t.add_node("0011001")
t.add_node("00110010")
t.add_node("00110011")
t.add_node("001100100")
t.add_node("001100101")
t.add_node("0011001010")
t.add_node("00110010101")
t.add_node("001100101010")
t.add_node("0011001010101")
t.add_node("0011001010100")
t.add_node("00110010101001")
t.add_node("001100101010010")
t.add_node("001100101010011")
t.add_node("0011001010100110")
t.add_node("0011001010100111")
t.add_node("00110010101001100")
t.add_node("001100101010011000")
t.add_node("00111")
t.add_node("001111")
t.add_node("0011110")
t.add_node("0011111")
t.add_node("00111110")
t.add_node("001111101")
t.add_node("0011111010")
t.add_node("00111110100")
t.add_node("001111101000")
t.add_node("0011111010000")
t.add_node("00111110100001")
t.add_node("001111101000010")
t.add_node("0011111010000101")
t.add_node("0001")
t.add_node("00010")
t.add_node("000100")
t.add_node("0001000")
t.add_node("00010001")
t.add_node("000100011")
t.add_node("000010010")
t.add_node("0000100101")
t.add_node("00001001011")
t.add_node("000010010110")
t.add_node("0000100101101")
t.add_node("00001001011010")
t.add_node("00001001011011")
t.add_node("00011")
t.add_node("000111")
t.add_node("000101")
t.add_node("0001010")
t.add_node("0001011")
t.add_node("00010110")
t.add_node("000101100")
t.add_node("0001011001")
t.add_node("00010110011")
t.add_node("000101100110")
t.add_node("0010110010")
t.add_node("00101100100")
t.add_node("001011001000")
t.add_node("0010110010000")
t.add_node("00101100100001")
t.add_node("001011001000011")
t.add_node("0010110010000111")
t.add_node("00101100100001110")
t.add_node("001011001001")
t.add_node("0010110010011")
t.add_node("00101100100110")
t.add_node("01")
t.add_node("010")
t.add_node("0100")
t.add_node("0101")
t.add_node("01000")
t.add_node("010000")
t.add_node("0100000")
t.add_node("01000001")
t.add_node("010000010")
t.add_node("0100000100")
t.add_node("01000001001")
t.add_node("010000010010")
t.add_node("010000010011")
t.add_node("0100000100110")
t.add_node("01000001001100")
t.add_node("01000001001101")
t.add_node("010000010011010")
t.add_node("0100000100110100")
t.add_node("01000001001101001")
t.add_node("010000010011010010")
t.add_node("0100000100110100101")
t.add_node("01000001001101001010")
t.add_node("010000010011010011")
t.add_node("0100000100110100111")
t.add_node("01000001001101001110")
t.add_node("010000010011010011100")
t.add_node("0100000100110100111000")
t.add_node("0100000100110100111001")
t.add_node("01000001001101001110011")
t.add_node("010000010011010011100110")
t.add_node("0100000100110100111001100")
#t.add_node("01000001001101001110011000")
#t.add_node("01000001001101001110011001")
t.add_node("010001")
t.add_node("0100011")
t.add_node("01000111")
t.add_node("010001110")
t.add_node("0100011100")
t.add_node("0100011101")
t.add_node("01000111011")
t.add_node("010001110111")
t.add_node("011")
t.add_node("0111")
t.add_node("01110")
t.add_node("011101")
t.add_node("0111011")
t.add_node("01110110")
t.add_node("01110111")
t.add_node("011101110")
t.add_node("0111011100")
t.add_node("01110111001")
t.add_node("011101110010")
t.add_node("0111011100100")
t.add_node("011101111")
t.add_node("0111011110")
t.add_node("0111011111")
t.add_node("01110111110")
t.add_node("011101111100")
t.add_node("0111011111000")
t.add_node("01110111110000")
t.add_node("01110111110001")
t.add_node("011101111100010")
t.add_node("0111011111000101")
t.add_node("01110111110001011")
t.add_node("011101111100010110")
t.add_node("0111011111000101100")
t.add_node("01110111110001011001")
t.add_node("011101111100010110010")
t.add_node("0111011111000101101")
t.add_node("01110111110001011010")
t.add_node("01110111110000100")
t.add_node("0111011111001")
t.add_node("01110111110011")
t.add_node("011101111100110")
t.add_node("0111011111001100")
t.add_node("01110111110011001")
t.add_node("011101111100110011")
t.add_node("0111011111001100111")
t.add_node("01110111110011001110")
t.add_node("011101111100110011100")
t.add_node("0111011111001100111000")
t.add_node("01110111110011001110000")
t.add_node("011101111100110011100001")
t.add_node("01110111110011001110001")
t.add_node("011101111100110011100011")
#t.add_node("0111011111001100111000110")
#t.add_node("01110111110011001110001101")
#t.add_node("011101111100110011100011010")
#t.add_node("0111011111001100111000110100")
#t.add_node("01110111110011001110001101001")
#t.add_node("011101111100110011100011010010")
#t.add_node("0111011111001100111000110100101")
t.add_node("01110111111")
t.add_node("01111")
t.add_node("1")
t.add_node("10")
t.add_node("100")
t.add_node("1000")
t.add_node("10000")
t.add_node("100001")
t.add_node("1000010")
t.add_node("10000100")
t.add_node("100001000")
t.add_node("100001001")
t.add_node("1000010010")
t.add_node("10000100100")
t.add_node("100001001000")
t.add_node("1000010010001")
t.add_node("10000100100011")
t.add_node("100001001000111")
t.add_node("1000010010001110")
t.add_node("10000100100011101")
t.add_node("100001001000111010")
t.add_node("1000010010001111")
t.add_node("100001001001")
t.add_node("1000011")
t.add_node("10000110")
t.add_node("10000111")
t.add_node("100001110")
t.add_node("100001111")
t.add_node("1000011110")
t.add_node("10000111101")
t.add_node("100001111010")
t.add_node("100001111011")
t.add_node("1000011110110")
t.add_node("10000111101100")
t.add_node("100001111011001")
t.add_node("1000011110110011")
t.add_node("10000111101100110")
t.add_node("10000111101100111")
t.add_node("100001111011001110")
t.add_node("100001111011001111")
t.add_node("10000111101101")
t.add_node("100001111011010")
t.add_node("1000011110110100")
t.add_node("10000111101101001")
t.add_node("1000011111")
t.add_node("1001")
t.add_node("10011")
t.add_node("100110")
t.add_node("1001100")
t.add_node("10011000")
t.add_node("100111")
t.add_node("1001110")
t.add_node("1001111")
t.add_node("10011110")
t.add_node("100111101")
t.add_node("1001111010")
t.add_node("10011110100")
t.add_node("100111101000")
t.add_node("1001111010001")
t.add_node("10011110100010")
t.add_node("10011111")
t.add_node("101")
t.add_node("1010")
t.add_node("10100")
t.add_node("101000")
t.add_node("1010001")
t.add_node("10100011")
t.add_node("101000110")
t.add_node("1010001100")
t.add_node("10100011001")
t.add_node("101000110011")
t.add_node("1011")
t.add_node("10110")
t.add_node("101100")
t.add_node("1011001")
t.add_node("10110011")
t.add_node("101100110")
t.add_node("1011001101")
t.add_node("10110011010")
t.add_node("101100110100")
t.add_node("1011001101000")
t.add_node("10110011010001")
t.add_node("101100110100010")
t.add_node("1011001101000101")
t.add_node("10110011010001010")
t.add_node("10110011010001011")
t.add_node("101100110100010110")
t.add_node("1011001101000101100")
t.add_node("10110011010001011001")
t.add_node("1011001101000101101")
t.add_node("101100101001")
t.add_node("1011001011")
t.add_node("101101")
t.add_node("10111")
t.add_node("101110")
t.add_node("1011100")
t.add_node("10111000")
t.add_node("101110000")
t.add_node("1011100000")
t.add_node("10111000001")
t.add_node("101110000010")
t.add_node("1011100000101")
t.add_node("10111000001011")
t.add_node("101110000010110")
t.add_node("1011100000101101")
t.add_node("10111000001011010")
t.add_node("101110000010110100")
t.add_node("1011100000101101000")
t.add_node("10111000001011010001")
t.add_node("101110000010110100010")
t.add_node("1011100000101101001")
t.add_node("101110000010111")
t.add_node("101110000011")
t.add_node("1011100001")
t.add_node("10111001")
t.add_node("101110010")
t.add_node("1011100100")
t.add_node("1011100101")
t.add_node("10111001010")
t.add_node("101110010101")
t.add_node("1011100101011")
t.add_node("10111001010110")
t.add_node("101110010101100")
t.add_node("101110010101101")
t.add_node("1011100101011010")
t.add_node("10111001010110101")
t.add_node("101110010101101010")
t.add_node("101110010101101011")
t.add_node("1011100101011010111")
t.add_node("10111001010110101110")
t.add_node("101110010101101011100")
t.add_node("1011100101011010111000")
t.add_node("10111001010110101110000")
t.add_node("10111001010110101110001")
t.add_node("101110010101101011100010")
#t.add_node("1011100101011010111000101")
#t.add_node("10111001010110101110001010")
#t.add_node("101110010101101011100010100")
#t.add_node("1011100101011010111000101001")
#t.add_node("10111001010110101110001010010")
#t.add_node("10111001010110101110001010011")
#t.add_node("101110010101101011100010100111")
#t.add_node("1011100101011010111000101001111")
#t.add_node("10111001010110101110001010011110")
#t.add_node("1011100101011010111000100")
t.add_node("10111001010110101111")
t.add_node("101110010101101011111")
t.add_node("1011100101011010111110")
t.add_node("1011100101011010111111")
t.add_node("10111001010110101111110")
t.add_node("101110010101101011111100")
t.add_node("1011100101011010111111001")
t.add_node("10111001010110101111110010")
t.add_node("10111001010110101111110011")
t.add_node("1011100101011011")
t.add_node("1100")
t.add_node("11000")
t.add_node("110000")
t.add_node("1100000")
t.add_node("11000000")
t.add_node("11000001")
t.add_node("110000010")
t.add_node("1100000101")
t.add_node("11000001011")
t.add_node("110000010110")
t.add_node("1100000101101")
t.add_node("11000001011010")
t.add_node("110000010110100")
t.add_node("1100000101101001")
t.add_node("1100001")
t.add_node("11000011")
t.add_node("11001")
t.add_node("110010")
t.add_node("1100100")
t.add_node("11001000")
t.add_node("110010000")
t.add_node("1100100000")
t.add_node("11001000001")
t.add_node("110010000010")
t.add_node("110010000011")
t.add_node("1100100000110")
t.add_node("11001000001101")
t.add_node("110010000011010")
t.add_node("1100100000110100")
t.add_node("11001000001101001")
t.add_node("110010000011010011")
t.add_node("1100100000110100110")
t.add_node("1100100000110100111")
t.add_node("11001000001101001110")
t.add_node("1100100000110100111000")
t.add_node("1100100000110100111001")
t.add_node("11001000001101001110011")
t.add_node("110010000011010011100110")
#t.add_node("1100100000110100111001100")
#t.add_node("11001000001101001110011000")
#t.add_node("110010000011010011100110000")
#t.add_node("1100100000110100111001100001")
#t.add_node("11001000001101001110011000011")
#t.add_node("110010000011010011100110000110")
#t.add_node("110010000011010011100110000111")
#t.add_node("1100100000110100111001100001110")
#t.add_node("11001000001101001110011000011101")
#t.add_node("110010000011010011100110000011010")
t.add_node("11001000001101001111")
t.add_node("110010000011010011110")
t.add_node("1100100000110100111100")
t.add_node("11001000001101001111000")
#t.add_node("110010000011010011110000")
#t.add_node("1100100000110100111100000")
#t.add_node("1100100000110100111100001")
#t.add_node("11001000001101001111000010")
t.add_node("110010000011011")
t.add_node("1100100000110110")
t.add_node("11001000001101101")
t.add_node("110010000011011010")
t.add_node("1100100000110110100")
t.add_node("11001000001101101000")
t.add_node("11001000001101101001")
t.add_node("110010000011011010010")
t.add_node("1100100000110110100100")
t.add_node("1100100000110110100101")
t.add_node("11001000001101101001011")
t.add_node("110010000011011010010110")
t.add_node("1101")
t.add_node("11011")
t.add_node("110110")
t.add_node("110111")
t.add_node("1101110")
t.add_node("11011100")
t.add_node("110111001")
t.add_node("1101110010")
t.add_node("11011100101")
t.add_node("110111001010")
t.add_node("110111001011")
t.add_node("1101111")
t.add_node("11011110")
t.add_node("110111100")
t.add_node("11011111")
t.add_node("110111110")
t.add_node("1101111100")
t.add_node("11011111000")
t.add_node("11011111001")
t.add_node("110111110010")
t.add_node("1101111100100")
t.add_node("11011111001001")
t.add_node("110111110010010")
t.add_node("1101111100100100")
t.add_node("11011111001001001")
t.add_node("110111110010010010")
t.add_node("110111110010010011")
t.add_node("1101111100100100110")
t.add_node("11011111001001001101")
t.add_node("1101111100100100110101")
t.add_node("110111110010010011011")
t.add_node("1101111100100100110111")
t.add_node("11011111001001001101110")
t.add_node("110111110010010011011100")
#t.add_node("1101111100100100110111001")
#t.add_node("11011111001001001101110010")
#t.add_node("110111110010010011011100101")
#t.add_node("1101111100100100110111001011")
#t.add_node("11011111001001001101110010111")
#t.add_node("110111110010010011011100101111")
#t.add_node("1101111100100100110111001011110")
#t.add_node("11011111001001001101110010111100")
#t.add_node("11011111001001001101110010111101")
#t.add_node("110111110010010011011100101111010")
t.add_node("111")
t.add_node("1110")
t.add_node("11100")
t.add_node("111000")
t.add_node("111001")
t.add_node("1110010")
t.add_node("11100100")
t.add_node("111001001")
t.add_node("1110010010")
t.add_node("11100100100")
t.add_node("111001001001")
t.add_node("1110010010011")
t.add_node("11100100100110")
t.add_node("111001001001101")
t.add_node("1110010010011010")
t.add_node("11100100100110100")
t.add_node("111001001001101001")
t.add_node("1110010010011010010")
t.add_node("11100100100110100100")
t.add_node("111001001001101001000")
t.add_node("1110010010011010010001")
t.add_node("11100100100110100100011")
t.add_node("111001001001101001000111")
#t.add_node("1110010010011010010001110")
#t.add_node("11100100100110100100011101")
#t.add_node("111001001001101001000111011")
#t.add_node("1110010010011010010001110110")
#t.add_node("11100100100110100100011101101")
#t.add_node("111001001001101001000111011011")
#t.add_node("1110010010011010010001110110110")
#t.add_node("11100100100110100100011101101101")
#t.add_node("1110010010011010010001110110111")
#t.add_node("11100100100110100100011101101110")
#t.add_node("1110010010011010010001111")
#t.add_node("11100100100110100100011111")
#t.add_node("111001001001101001000111111")
#t.add_node("1110010010011010010001111110")
#t.add_node("11100100100110100100011111101")
#t.add_node("111001001001101001000111111010")
#t.add_node("1110010010011010010001111110100")
#t.add_node("11100100100110100100011111101000")
#t.add_node("11100100100110100100011111101001")
t.add_node("1110010010011010011")
t.add_node("11100100100110100111")
t.add_node("111001001001101001110")
t.add_node("1110010010011010011100")
t.add_node("11100100100110100111001")
#t.add_node("111001001001101001110010")
#t.add_node("1110010010011010011100101")
#t.add_node("11100100100110100111001011")
t.add_node("1110010010011010011101")
t.add_node("11100100100110100111011")
t.add_node("111001001001101001110110")
#t.add_node("1110010010011010011101100")
#t.add_node("1110010010011010011101101")
#t.add_node("11100100100110100111011010")
#t.add_node("111001001001101001110110100")
#t.add_node("1110010010011010011101101000")
#t.add_node("11100100100110100111011010001")
t.add_node("11100100100111")
t.add_node("111001001001110")
t.add_node("1110010010011101")
t.add_node("11100100100111011")
t.add_node("111001001001110110")
t.add_node("1110010010011101101")
t.add_node("11100100100111011010")
t.add_node("1110010011")
t.add_node("11100100110")
t.add_node("111001001100")
t.add_node("111001001101")
t.add_node("1110010011010")
t.add_node("11100100110100")
t.add_node("111001001101001")
t.add_node("1110010011010010")
t.add_node("11100100110100101")
t.add_node("111001001101001011")
t.add_node("1110010011010010111")
t.add_node("11100100110100101111")
t.add_node("111001001101001011110")
t.add_node("1110010011010010111101")
t.add_node("11100100110100101111010")
t.add_node("111001001101001011110101")
#t.add_node("1110010011010010111101010")
#t.add_node("11100100110100101111010100")
#t.add_node("111001001101001011110101000")
#t.add_node("111001001101001011110101001")
#t.add_node("1110010011010010111101010010")
#t.add_node("11100100110100101111010100101")
#t.add_node("111001001101001011110101001011")
#t.add_node("1110010011010010111101010010111")
#t.add_node("11100100110100101111010100101110")
t.add_node("111001001101001011111")
t.add_node("1110010011010010111111")
t.add_node("11100100110100101111111")
t.add_node("111001001101001011111110")
#t.add_node("1110010011010010111111101")
#t.add_node("11100100110100101111111011")
#t.add_node("111001001101001011111110110")
#t.add_node("1110010011010010111111101101")
t.add_node("11101")
t.add_node("111010")
t.add_node("1110100")
t.add_node("11101000")
t.add_node("111010000")
t.add_node("111010001")
t.add_node("1110100010")
t.add_node("11101000101")
t.add_node("111010001011")
t.add_node("1110100010110")
t.add_node("11101000101100")
t.add_node("111010001011001")
t.add_node("1110100010110010")
t.add_node("11101000101100100")
t.add_node("111010001011001001")
t.add_node("1110100010110010011")
t.add_node("11101000101100100111")
t.add_node("111010001011001001111")
t.add_node("1110100010110010011110")
t.add_node("11101000101100100111100")
t.add_node("111010001011001001111001")
#t.add_node("1110100010110010011110010")
#t.add_node("11101000101100100111100101")
#t.add_node("111010001011001001111001010")
#t.add_node("111010001011001001111001011")
#t.add_node("1110100010110010011110010111")
#t.add_node("11101000101100100111100101111")
#t.add_node("111010001011001001111001011110")
#t.add_node("1110100010110010011110010111100")
t.add_node("1110100010110011")
t.add_node("11101000101101")
t.add_node("1110100011")
t.add_node("11101001")
t.add_node("111011")
t.add_node("1110110")
t.add_node("11101100")
t.add_node("11101101")
t.add_node("111011010")
t.add_node("1110110100")
t.add_node("1110110101")
t.add_node("11101101010")
t.add_node("11101101011")
t.add_node("111011010110")
t.add_node("1110110101100")
t.add_node("11101101011000")
t.add_node("111011010110001")
t.add_node("1110110101100010")
t.add_node("11101101011000100")
t.add_node("111011010110001001")
t.add_node("1110110101100010011")
t.add_node("11101101011000100110")
t.add_node("111011010110001001101")
t.add_node("1110110101100010011011")
t.add_node("11101101011000100110110")
t.add_node("111011010110001001101100")
#t.add_node("1110110101100010011011000")
#t.add_node("1110110101100010011011001")
#t.add_node("11101101011000100110110011")
#t.add_node("111011010110001001101100111")
#t.add_node("1110110101100010011011001110")
#t.add_node("1110110101100010011011001111")
#t.add_node("11101101011000100110110011110")
t.add_node("111011010110001001101101")
#t.add_node("1110110101100010011011010")
#t.add_node("11101101011000100110110101")
#t.add_node("111011010110001001101101011")
#t.add_node("1110110101100010011011010111")
#t.add_node("11101101011000100110110101110")
#t.add_node("111011010110001001101101011101")
#t.add_node("1110110101100010011011010111010")
#t.add_node("11101101011000100110110101110100")
t.add_node("111011010111")
t.add_node("1110110101111")
t.add_node("11101101011110")
t.add_node("11101101011111")
t.add_node("111011010111110")
t.add_node("1110110101111100")
t.add_node("11101101011111101")
t.add_node("111011010111111010")
t.add_node("1110110101111110101")
t.add_node("11101101011111101010")
t.add_node("111011010111111010101")
t.add_node("111011010111111011")
t.add_node("1110110101111110110")
t.add_node("11101101011111101101")
t.add_node("111011010111111011010")
t.add_node("1110110101111110110100")
t.add_node("11101101011111101101000")
t.add_node("111011010111111011010001")
t.add_node("1110110101111110110101")
t.add_node("11101101011111101101010")
t.add_node("111011010111111011010100")
#t.add_node("1110110101111110110101000")
#t.add_node("11101101011111101101010000")
#t.add_node("111011010111111011010100000")
#t.add_node("1110110101111110110100000001")
t.add_node("1111")
t.add_node("11110")
t.add_node("111100")
t.add_node("1111001")
t.add_node("11110010")
t.add_node("11110011")
t.add_node("111100111")
t.add_node("1111001110")
t.add_node("11110011100")
t.add_node("11110011101")
t.add_node("111100111010")
t.add_node("111100111011")
t.add_node("1111001110111")
t.add_node("11110011101110")
t.add_node("111100111011101")
t.add_node("1111001110111011")
t.add_node("11110011101110111")
t.add_node("111100111011101111")
t.add_node("1111001110111011110")
t.add_node("11110011101110111101")
t.add_node("111100111011101111010")
t.add_node("1111001111")
t.add_node("11110011111")
t.add_node("111100111110")
t.add_node("1111001111101")
t.add_node("11110011111010")
t.add_node("111100111110101")
t.add_node("1111001111101010")
t.add_node("11110011111010100")
t.add_node("111100111110101000")
t.add_node("1111001111101010001")
t.add_node("11110011111010100010")
t.add_node("111100111110101000101")
t.add_node("1111001111101010001010")
t.add_node("11110011111010100010101")
t.add_node("111100111110101000101011")
#t.add_node("1111001111101010001010110")
#t.add_node("11110011111010100010101101")
#t.add_node("111100111110101000101011010")
#t.add_node("1111001111101010001010110101")
#t.add_node("11110011111010100010101101011")
#t.add_node("111100111110101000101011010110")
#t.add_node("1111001111101010001010110101101")
#t.add_node("111100111110101000101011011")
#t.add_node("1111001111101010001010110110")
#t.add_node("11110011111010100010101101101")
#t.add_node("111100111110101000101011011010")
#t.add_node("1111001111101010001010110110101")
#t.add_node("11110011111010100010101101101011")
t.add_node("1110101")
t.add_node("11101010")
t.add_node("11101011")
t.add_node("11111")
t.add_node("111110")
t.add_node("1111000")
t.add_node("111100101")
t.add_node("1111001010")
t.add_node("11110010101")
t.add_node("11110010100")
t.add_node("111100101000")
t.add_node("111100101011")
t.add_node("1111001010110")
t.add_node("11110010101101")
t.add_node("111100101011010")
t.add_node("1111001010110101")
t.add_node("11110010101101010")
t.add_node("11110010101101011")
t.add_node("111100101011010111")
t.add_node("1111001010110101110")
t.add_node("11110010101101011100")
t.add_node("111100101011010111001")
t.add_node("1111001010110101110010")
t.add_node("1111001010110101110011")
t.add_node("1111100")
t.add_node("11111001")
t.add_node("111110010")
t.add_node("1111100100")
t.add_node("11111001001")
t.add_node("111110010010")
t.add_node("1111100100101")
t.add_node("11111001001010")
t.add_node("111110010010100")
t.add_node("1111100100101000")
t.add_node("11111001001010000")
t.add_node("111110010010100000")
t.add_node("1111100100101000001")
t.add_node("11111001001010000010")
t.add_node("111110010010100000101")
t.add_node("1111100100101000001010")
t.add_node("11111001001010000010101")
t.add_node("111110010010100000101011")
#t.add_node("1111100100101000001010110")
#t.add_node("1111100100101000001010111")
#t.add_node("11111001001010000010101111")
#t.add_node("111110010010100000101011110")
#t.add_node("1111100100101000001010111101")
#t.add_node("11111001001010000010101111010")
#t.add_node("111110010010100000101011110100")
#t.add_node("1111100100101000001010111101001")
#t.add_node("11111001001010000010101111010011")
t.add_node("11111001001010001")
t.add_node("111110010010100011")
t.add_node("1111100100101000110")
t.add_node("11111001001010001101")
t.add_node("111110010010100011010")
t.add_node("1111100100101000110101")
t.add_node("11111001001010001101010")
t.add_node("111110010010100011010100")
#t.add_node("1111100100101000110101000")
#t.add_node("11111001001010001101010001")
#t.add_node("111110010010100011010100010")
t.add_node("11111001001010001101011")
t.add_node("111110010010100011010110")
t.add_node("111110010010100011010111")
#t.add_node("1111100100101000110101110")
#t.add_node("11111001001010001101011101")
t.add_node("1111100101")
t.add_node("11111001011")
t.add_node("111110010110")
t.add_node("1111100101100")
t.add_node("11111001011000")
t.add_node("11111001011001")
t.add_node("111110010110011")
t.add_node("1111100101100110")
t.add_node("11111001011001100")
t.add_node("111110010110011001")
t.add_node("1111100101100110010")
t.add_node("11111001011001100101")
t.add_node("111110010110011001010")
t.add_node("111110010110011001011")
t.add_node("1111100101100110010111")
t.add_node("11111001011001100101110")
t.add_node("111110010110011001011101")
t.add_node("1111100101101")
t.add_node("11111001011011")
t.add_node("111110010110110")
t.add_node("1111100101101101")
t.add_node("11111001011011011")
t.add_node("111110010110110110")
t.add_node("1111100101101101101")
t.add_node("11111001011011011011")
t.add_node("111110010110110110110")
t.add_node("1111100101101101101100")
t.add_node("11111001011011011011001")
t.add_node("111110010110110110111")
t.add_node("1111100101101101101111")
t.add_node("11111001011011011011110")
t.add_node("111110010110110110111101")
#t.add_node("1111100101101101101111011")
#t.add_node("11111001011011011011110110")
#t.add_node("111110010110110110111101101")
#t.add_node("1111100101101101101111011010")
#t.add_node("11111001011011011011110110101")
#t.add_node("111110010110110110111101101010")
#t.add_node("111110010110110110111101101011")
#t.add_node("1111100101101101101111011010111")
#t.add_node("11111001011011011011110110101110")
t.add_node("111111")
t.add_node("1111110")
t.add_node("11111100")
t.add_node("111111001")
t.add_node("1111110010")
t.add_node("11111100101")
t.add_node("111111001011")
t.add_node("1111110010110")
t.add_node("11111100101101")
t.add_node("111111001011011")
t.add_node("1111110010110110")
t.add_node("11111100101101101")
t.add_node("111111001011011011")
t.add_node("1111110010110110110")
t.add_node("11111100101101101101")
t.add_node("111111001011011011011")
t.add_node("1111110010110110110110")
t.add_node("11111100101101101101101")
t.add_node("111111001011011011011011")
#t.add_node("1111110010110110110110110")
#t.add_node("11111100101101101101101100")
#t.add_node("111111001011011011011011001")
#t.add_node("1111110010110110110110110011")
#t.add_node("11111100101101101101101100111")
#t.add_node("111111001011011011011011001110")
#t.add_node("1111110010110110110110110011101")
#t.add_node("11111100101101101101101100111010")
#t.add_node("11111100101101101101101101")
#t.add_node("111111001011011011011011010")
#t.add_node("111111001011011011011011011")
#t.add_node("1111110010110110110110110111")
#t.add_node("11111100101101101101101101110")
#t.add_node("111111001011011011011011011101")
#t.add_node("1111110010110110110110110111010")
#t.add_node("11111100101101101101101101110101")
t.add_node("1111111")


#t.add_gw("100001111011", 0, "135.176.0.254", None);
#t.add_gw("1000011110110100", 0, "135.180.0.254", None);
#t.add_gw("111100111110101000101011", 0, "243.234.43.0", None);
t.add_gw("00001010",0, "10.0.0.254", None);
t.add_gw("00100000",0, "32.0.0.254", None);
t.add_gw("00101100",0, "44.0.0.254", None);
t.add_gw("00111110",0, "62.0.0.254", None);
t.add_gw("01000001",0, "65.0.0.254", None);
t.add_gw("01110111",0, "119.0.0.254", None);
t.add_gw("10000100",0, "132.0.0.254", None);
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
        self.switch["10.0.0.254"  ] = ["10.0.0.254","8" ,"00:00:00:11:11:01","s1","1"]
        self.switch["32.0.0.254"] = ["32.0.0.254","8","00:00:00:11:11:02","s2","2"]
        self.switch["44.0.0.254"] = ["44.0.0.254","8","00:00:00:11:11:03","s3","3"]
        self.switch["62.0.0.254"] = ["62.0.0.254","8","00:00:00:11:11:04","s4","4"]
        self.switch["65.0.0.254"] = ["65.0.0.254", "8", "00:00:00:11:11:05", "s5", "5"]
        self.switch["119.0.0.254"] = ["119.0.0.254", "8", "00:00:00:11:11:06", "s6", "6"]
        self.switch["132.0.0.254"] = ["132.0.0.254", "8", "00:00:00:11:11:07", "s7", "7"]
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
        self.ip_to_mac["10.0.0.1"] = "00:00:00:00:00:01"
        self.ip_to_mac["10.0.0.2"] = "00:00:00:00:00:02"
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
        self.ip_to_mac["119.0.0.1"] = "00:00:00:00:00:0d"
        self.ip_to_mac["119.0.0.2"] = "00:00:00:00:00:0e"
        self.ip_to_mac["132.0.0.1"] = "00:00:00:00:00:0f"
        self.ip_to_mac["132.0.0.2"] = "00:00:00:00:00:10"
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


