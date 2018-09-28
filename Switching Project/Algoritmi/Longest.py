#!/usr/bin/python
import math

ipRicercato = '10000000'
#ipRicercato = '11000011'

#costruzione della tabella dei prefissi

ipLookUp = [ipLookUp[:] for ipLookUp in [[0]*(len(ipRicercato)-1)]*7]
marker = [marker[:] for marker in [[0]*(len(ipRicercato)-1)]*7]
print ipLookUp

#tabella prefissi
ipLookUp[0] = []
ipLookUp[1] = ['0','1','00','01','10','001','000','110']
ipLookUp[2] = []
ipLookUp[3] = ['0000','0001','0100','1000']
ipLookUp[4] = []
ipLookUp[5] = ['10000','00010','000010','000011','000100','100100','0000100','1100000','1001001','1001001']
ipLookUp[6] = []

#tabella marker
#marker[1] = ['11']
#marker[3] = ['1100','1001']
#marker[5] = ['110000','010011']

#visualizzazione della tabella
x=0;
y=0;
print ipLookUp,"\n"
for x in range(0,len(ipLookUp)):
    for y in range(0,len(ipLookUp[x])):
        print ipLookUp[x][y],"\t"
    print " "



#primo indice per la ricerca
index = int(round(len(ipLookUp)/2)+1)

#profondita' dell'albero
deepMax = int(math.log(len(ipLookUp)+1,2))
deep = 0

#costruzione dell'albero
albero = [albero[:] for albero in [[0]*(len(ipRicercato)-1)]*(deepMax)]
x=0
y=0
for x in range(0,deepMax):
    riga=index
    
    for y in range (0,((2**(x+1))-1)):
     
        albero[x][y]=riga
        riga = riga + index
    
    index = int(index/2)

print albero,"\n"

indice = 0

#ricerca di un valore
def ricerca(ipRicercato,deepCurrent,indice):
    
    ipTagliato = ipRicercato[0:albero[deepCurrent][indice]]
    print "\nipTagliato: ",ipTagliato
    print "deepCurrent",deepCurrent
    print "deepMax",deepMax
    if deepCurrent == deepMax-2:
        ipTagliatoMenoUno = ipRicercato[0:(albero[deepCurrent][indice]-1)]
        ipTagliatoPiuUno = ipRicercato[0:(albero[deepCurrent][indice]+1)]
        #print deepCurrent, ipTagliatoMenoUno, ipTagliatoPiuUno
    
    print "index: ",albero[deepCurrent][indice]
    print "Tabella ",ipLookUp[albero[deepCurrent][indice]-1]
    trovato = 0
    
    
    if(deepCurrent < deepMax-1 and deepCurrent != deepMax-2):
        if ipTagliato in ipLookUp[albero[deepCurrent][indice]-1]:
            
            print "ip trovato"
            
            if(deepCurrent < deepMax-1):
                indice = albero[deepCurrent+1].index(albero[deepCurrent][indice]) +1

        
        else:
            if ipTagliato in marker[albero[deepCurrent][indice]-1]:
                print "ho trovato un marker"
                indice = albero[deepCurrent+1].index(albero[deepCurrent][indice]) +1
            else:
                print "ip NON trovato"
                if(deepCurrent < deepMax-1):
                    indice = albero[deepCurrent+1].index(albero[deepCurrent][indice]) -1
                    
    
    if(deepCurrent < deepMax-1 and deepCurrent == deepMax-2):
        if ipTagliato in ipLookUp[albero[deepCurrent][indice]-1] or ipTagliatoMenoUno in ipLookUp[albero[deepCurrent][indice]-1] or ipTagliatoPiuUno in ipLookUp[albero[deepCurrent][indice]-1]:
            
            print "ip trovato"
            
            #if(deepCurrent < deepMax-1):
            #    indice = albero[deepCurrent+1].index(albero[deepCurrent][indice]) +1

        
        else:
            if ipTagliato in marker[albero[deepCurrent][indice]-1]:
                print "ho trovato un marker"
                indice = albero[deepCurrent+1].index(albero[deepCurrent][indice]) +1
            else:
                print "ip NON trovato"
                if(deepCurrent < deepMax-1):
                    indice = albero[deepCurrent+1].index(albero[deepCurrent][indice]) -1    
    deepCurrent = deepCurrent+1
    if (deepCurrent < deepMax-1 and albero[deepCurrent][indice] != 0):
        ricerca(ipRicercato,deepCurrent,indice)
    

    else:
        return
print "ipRicercato: ",ipRicercato
print "\nInizio Ricerca\n"
ricerca(ipRicercato,deep,indice)
