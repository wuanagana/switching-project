# IMPORT LIBRARIES
import json
import math
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
from datatime import datatime


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
#########################################################
NROW   = 8   #numero di switch con stessa lunghezza del prefisso (max righe della tabella)

#########################################################

#funzione da decimale a binario
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
	
	
ipLookUp = [ipLookUp[:] for ipLookUp in [[0]*(32-1)]*31]
marker = [marker[:] for marker in [[0]*(32-1)]*31]
#tabella dei prefissi
ipLookUp[0] = ['']
ipLookUp[1] = ['']
ipLookUp[2] = ['']
ipLookUp[3] = ['']
ipLookUp[4] = ['']
ipLookUp[5] = ['']
ipLookUp[6] = ['']
ipLookUp[7] = ['10000111','11000011']
ipLookUp[8] = ['']
ipLookUp[9] = ['']
ipLookUp[10] = ['']
ipLookUp[11] = ['100001111011']
ipLookUp[12] = ['']
ipLookUp[13] = [''] 
ipLookUp[14] = ['']
ipLookUp[15] = ['1000011110110100','1111001111101010']
ipLookUp[16] = ['']
ipLookUp[17] = ['']
ipLookUp[18] = ['']
ipLookUp[19] = ['']
ipLookUp[20] = ['']
ipLookUp[21] = ['']
ipLookUp[22] = ['']
ipLookUp[23] = ['111100111110101000101011']
ipLookUp[24] = ['']
ipLookUp[25] = ['']
ipLookUp[26] = ['']
ipLookUp[27] = ['']
ipLookUp[28] = ['']
ipLookUp[29] = ['']
ipLookUp[30] = ['']

#tabella marker
marker[1] = []
marker[3] = []
marker[5] = []

#indice di partenza per la ricerca
index = int(round(len(ipLookUp)/2)+1)

#profondita' del percorso dell'algoritmo
deepMax = int(math.log(len(ipLookUp)+1,2))
deep = 0

#dizionario per mappatura prefisso-indirizzo di rete
binary2ip = {}
binary2ip['1000011110110100']='135.180.0.254'
binary2ip['111100111110101000101011']='243.234.43.254'
binary2ip['100001111011']='135.176.0.254'
binary2ip['11000011']='195.0.0.254'

#costruzione passaggi dell'algoritmo
albero = [albero[:] for albero in [[0]*(31)]*(deepMax)]
for x in range(0,deepMax):
    riga=index
    
    for y in range (0,((2**(x+1))-1)):
     
        albero[x][y]=riga
        riga = riga + index
    
    index = int(index/2)

#variabili globali algoritmo
indice = 0
gateway = 0

#ricerca di un valore
def ricerca(ipRicercato,deepCurrent,indice):
    global gateway
    #print ipRicercato  
    ipTagliato = ipRicercato[0:albero[deepCurrent][indice]]
    #print "\nipTagliato: ",ipTagliato
    #print "index: ",albero[deepCurrent][indice]
    #print "Tabella ",ipLookUp[albero[deepCurrent][indice]-1]
    trovato = 0
    if(deepCurrent < deepMax):
        if ipTagliato in ipLookUp[albero[deepCurrent][indice]-1]:
            #print "ip trovato"
            gateway = ipTagliato
            if(deepCurrent < deepMax-1):
                indice = albero[deepCurrent+1].index(albero[deepCurrent][indice]) +1
        else:
            if ipTagliato in marker[albero[deepCurrent][indice]-1]:
                #print "ho trovato un marker"
                indice = albero[deepCurrent+1].index(albero[deepCurrent][indice]) +1
            else:
                #print "ip NON trovato"
                if(deepCurrent < deepMax-1):
                    indice = albero[deepCurrent+1].index(albero[deepCurrent][indice]) -1

    deepCurrent = deepCurrent+1
    
    if (deepCurrent < deepMax and albero[deepCurrent][indice] != 0):
        ricerca(ipRicercato,deepCurrent,indice)
    else:
        #print ipTagliato
        
        return 

########################################################

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


        self.mac_to_port["1"]["00:00:00:00:00:01"] = 1
        self.mac_to_port["1"]["00:00:00:00:00:02"] = 2
        self.mac_to_port["2"]["00:00:00:00:00:03"] = 1
        self.mac_to_port["2"]["00:00:00:00:00:04"] = 2
        self.mac_to_port["3"]["00:00:00:00:00:05"] = 1
        self.mac_to_port["3"]["00:00:00:00:00:06"] = 2
        self.mac_to_port["4"]["00:00:00:00:00:07"] = 1
        self.mac_to_port["4"]["00:00:00:00:00:08"] = 2

        self.switch = {}
        self.switch["195.0.0.254"  ] = ["195.0.0.254","8" ,"00:00:00:11:11:01","s1","1"] 
        self.switch["135.176.0.254"] = ["135.176.0.254","12","00:00:00:11:11:02","s2","2"] 
        self.switch["135.180.0.254"] = ["135.180.0.254","16","00:00:00:11:11:03","s3","3"] 
        self.switch["243.234.43.254"] = ["243.234.43.254","24","00:00:00:11:11:04","s4","4"] 

        self.lookup = {}
        self.lookup["195.0.0.1"]   = "195.0.0.254"
        self.lookup["195.0.0.2"]   = "195.0.0.254"
        self.lookup["135.176.0.1"] = "135.176.0.254"
        self.lookup["135.176.0.2"] = "135.176.0.254"
        self.lookup["135.180.0.1"] = "135.180.0.254"
        self.lookup["135.180.0.2"] = "135.180.0.254"
        self.lookup["243.234.43.1"] = "243.234.43.254"
        self.lookup["243.234.43.2"] = "243.234.43.254"

        self.ip_to_mac = {}
        self.ip_to_mac["195.0.0.1"]   = "00:00:00:00:00:01"
        self.ip_to_mac["195.0.0.2"]   = "00:00:00:00:00:02"
        self.ip_to_mac["135.176.0.1"] = "00:00:00:00:00:03"
        self.ip_to_mac["135.176.0.2"] = "00:00:00:00:00:04"
        self.ip_to_mac["135.180.0.1"] = "00:00:00:00:00:05"
        self.ip_to_mac["135.180.0.2"] = "00:00:00:00:00:06"
        self.ip_to_mac["243.234.43.1"] = "00:00:00:00:00:07"
        self.ip_to_mac["243.234.43.2"] = "00:00:00:00:00:08"

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
            global gateway
            self.logger.info("  --- IP LOOKUP")
            src_ip = ip4_pkt.src
            dst_ip = ip4_pkt.dst
            self.logger.info("  --- src_ip[%s], dst_ip[%s]" % (src_ip,dst_ip))
            
            ipRicercato = fromIPtoBinary(dst_ip)
	    t1 = datatime.now()
	    ricerca(ipRicercato,deep,indice);
	    t2 = datatime.now()
	    self.logger.info('\n\n##########Duration: {}'.format(t2 - t1))
	    sw = binary2ip[gateway]
	    gateway = None
			
            if sw is not None:
            #if dst_ip in self.lookup:
                #sw = self.lookup[dst_ip]
                
                self.logger.info("  --- Destination present on switch %s" % (self.switch[sw]))
                dp = get_datapath(self,int(self.switch[sw][DPID]))

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


