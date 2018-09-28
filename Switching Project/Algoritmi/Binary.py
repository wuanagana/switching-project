#!/usr/bin/python
from collections import deque

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
		if node is None:
			node = self.root

		if self.root.key == key:
			node.add_gw(gateway)
			print "Gateway added to the root: ", node.gateway
			l = 0;
			return 
		else:
			if len(node.key) == len(key) and node.key[0:(l)] == key:
				print "Gateway added to node: ", node.key
				node.add_gw(gateway)
				l = 0
				return 
			elif key[l] == "0" and node.left is not None:
				l = l + 1
				return self.add_gw(key, l, gateway, node = node.left)
			
			elif key[l] == "1" and node.right is not None:
				l = l + 1
				return self.add_gw(key, l, gateway, node = node.right)
			else:
				l = 0;
				return None
	
	#print of the tree with nodes ordered by level	
	def print_tree(self, head, queue=deque()):
		if head is None:
       			return
    		print "\nkey: ", head.key, "\nGw: ", head.gateway
		if head.right is not None:
			print "Node dx: ", head.right.key
		else:	print "Node dx:  --"
		if head.left is not None:
			print "Node sx: ", head.left.key
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
	


		
			
			
		
length=0
last_prefix=None 
t=Tree()
t.add_node("*")
t.add_node("0")
t.add_node("1")
t.add_node("01")
t.add_node("00")
t.add_node("001")
t.add_node("0010")
t.add_node("0011")
t.add_node("00110")
t.add_node("001101")
t.add_node("10")
t.add_node("11")
t.add_node("100")
t.add_node("101")
t.add_node("1010")
t.add_node("1011")
t.add_node("10110")
t.add_node("101100")
t.add_node("101101")
t.add_node("00000000000000000000000000000000")


t.add_gw("*", 0, "DEFAULT", None);
t.add_gw("0", 0, "255.255.255.254", None);
t.add_gw("1", 0, "255.255.255.253", None);
t.add_gw("101", 0, "195.15.0.127", None);
t.add_gw("01", 0, "15.15.15.15", None);
t.add_gw("00", 0, "15.14.13.12", None);
t.add_gw("0010", 0, "128.30.30.30", None);
t.add_gw("001101", 0, "128.15.0.0", None);
t.add_gw("10110", 0, "64.128.0.0", None);

print "#########################\nRicerca per nodo: 0.0.0.0"
x=t.finding_prefix("0.0.0.0",t.root,0)
print "Gateway found: ", x,"\n#########################"

#t.print_tree(t.root)
