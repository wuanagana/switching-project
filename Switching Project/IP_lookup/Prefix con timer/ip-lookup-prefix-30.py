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
ipLookUp[7] = ['00001011','00100000','00101100','00111110','01000001','01111000','10000101','10011110','10111000','11000011','00001010','0010000','00110010','0100000','10000100','10000111','10011110','10111001','10111000','01110111']
ipLookUp[8] = ['']
ipLookUp[9] = ['']
ipLookUp[10] = ['']
ipLookUp[11] = ['000010101100','001000010110','001100101010','010000010011','100001001000','100001111011','100111101000','101110010101','101110000010','011101110010']
ipLookUp[12] = ['']
ipLookUp[13] = [''] 
ipLookUp[14] = ['']
ipLookUp[15] = ['']
ipLookUp[16] = ['']
ipLookUp[17] = ['']
ipLookUp[18] = ['']
ipLookUp[19] = ['']
ipLookUp[20] = ['']
ipLookUp[21] = ['']
ipLookUp[22] = ['']
ipLookUp[23] = ['']
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
binary2ip['00001011']='11.0.0.254'
binary2ip['00100000']='32.0.0.254'
binary2ip['00101100']='44.0.0.254'
binary2ip['00111110']='62.0.0.254'
binary2ip['01000001']='65.0.0.254'
binary2ip['01111000']='120.0.0.254'
binary2ip['10000101']='133.0.0.254'
binary2ip['10011110']='158.0.0.254'
binary2ip['10111000']='184.0.0.254'
binary2ip['11000011']='195.0.0.254'
binary2ip['000010101100']='10.192.0.254'
binary2ip['001000010110']='33.96.0.254'
binary2ip['001100101010']='50.160.0.254'
binary2ip['010000010011']='65.48.0.254'
binary2ip['100001001000']='132.128.0.254'
binary2ip['100001111011']='135.176.0.254'
binary2ip['100111101000']='158.128.0.254'
binary2ip['101110010101']='185.80.0.254'
binary2ip['101110000010']='184.32.0.254'
binary2ip['011101110010']='119.32.0.354'


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


