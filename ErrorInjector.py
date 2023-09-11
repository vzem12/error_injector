import PySimpleGUI as sg
from scapy.all import *
from time import sleep
from socket import *
from portio import *
import os, sys
import netfilterqueue
import zlib
import psutil
import re
from threading import Thread
import random
import time
# =====================================Дефолтные настройки===========================================

print('Интерфейсы для CPE и User указываются в defconf')
f = open('defconf', 'r')
while True:
    line = f.readline()
    if "User MAC" in line:
        User_MAC = re.search(r'\S+:\S+:\S+:\S+:\S+:\S+', line)[0]
    if "CPE MAC" in line:
        CPE_MAC = re.search(r'\S+:\S+:\S+:\S+:\S+:\S+', line)[0]
    if "User interface" in line:
        EthtoUserstream = re.search(r':\s*\S+', line)[0][1:].strip()
    if "CPE interface" in line:
        EthtoCPEstream = re.search(r':\s*\S+', line)[0][1:].strip()
    if "Buffer Size" in line:
        buffer_size = int(re.search(r':\s*\S+', line)[0][1:].strip())
    if not line:
        break
f.close
iface_br = 'br0'
EnableCRC = False
EnableDelay = False
EnableDrop = False

CRCChance = 1000
DelayTime = 50
DelayChance = 10
DropChance = 0.1

CRC_User = False
Delay_User = True
Drop_User = True

CRC_CPE = True
Delay_CPE = False
Drop_CPE = False

RXQueue = Queue(buffer_size)
TXQueue = Queue(buffer_size)

latency = 0.1

RXPreTime = 0
TXPreTime = 0
RXTime = 0
TXTime = 0

# ==================================================================================================

def mac_to_byte(mac):
    byte_mac = b''
    for i in range(6):
        byte_mac += bytes([int(mac[i*2:i*2+2], 16)])
    return byte_mac
    
#===============CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=============

def user_stream_crc_broadcast():
    Socket = socket(AF_PACKET, SOCK_RAW)
    Socket.setsockopt(SOL_SOCKET, 43, 1)
    Socket.bind((EthtoCPEstream, 0))
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, lambda pkt: user_send_crc_broadcast(pkt, Socket))
    try:
        queue.run()
    except:
        queue.unbind()
    
    
def user_send_crc_broadcast(pkt, Socket):
    global CRCtoCPECounter
    global CRCtoCPEStat
    if CRC and CRCtoCPE:
        CRCtoCPECounter += 1
        if CRCtoCPECounter >= CRCChance:
            packet = b'\xff\xff\xff\xff\xff\xff' + pkt.get_hw()[:-2] + b'\x08\x00' + pkt.get_payload() + b'\x09\x09\x09\x09'
            Socket.send(packet)
            pkt.drop()
            CRCtoCPECounter = 0
            CRCtoCPEStat += 1
        elif CRCtoCPECounter < CRCChance:
            pkt.accept()
    else:
        pkt.accept()
        
        
def user_stream_crc_multicast():
    Socket = socket(AF_PACKET, SOCK_RAW)
    Socket.setsockopt(SOL_SOCKET, 43, 1)
    Socket.bind((EthtoCPEstream, 0))
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1, lambda pkt: user_send_crc_multicast(pkt, Socket))
    try:
        queue.run()
    except:
        queue.unbind()
        
    
def user_send_crc_multicast(pkt, Socket):
    global CRCtoCPECounter
    global CRCtoCPEStat
    if CRC and CRCtoCPE:
        CRCtoCPECounter += 1
        if CRCtoCPECounter >= CRCChance:
            dst_ip = pkt.get_payload()[16:20]
            if dst_ip[1] < 128:
                octet_4 = bytes([dst_ip[1]])
            else:
                octet_4 = bytes([dst_ip[1] - 0b10000000])
            packet = b'\x01\x00\x5e' + octet_4 + dst_ip[2:] + pkt.get_hw()[:-2] + b'\x08\x00' + pkt.get_payload() + b'\x09\x09\x09\x09'
            Socket.send(packet)
            pkt.drop()
            CRCtoCPECounter = 0
            CRCtoCPEStat += 1
        elif CRCtoCPECounter < CRCChance:
            pkt.accept()
    else:
        pkt.accept()
        
        
def user_stream_crc_unicast():
    Socket = socket(AF_PACKET, SOCK_RAW)
    Socket.setsockopt(SOL_SOCKET, 43, 1)
    Socket.bind((EthtoCPEstream, 0))
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(2, lambda pkt: user_send_crc_unicast(pkt, Socket))
    try:
        queue.run()
    except:
        queue.unbind()
        
    
def user_send_crc_unicast(pkt, Socket):
    global CRCtoCPECounter
    global CRCtoCPEStat
    if CRC and CRCtoCPE:
        CRCtoCPECounter += 1
        if CRCtoCPECounter >= CRCChance:
            packet = CPEMACByte + pkt.get_hw()[:-2] + b'\x08\x00' + pkt.get_payload() + b'\x09\x09\x09\x09'
            Socket.send(packet)
            pkt.drop()
            CRCtoCPECounter = 0
            CRCtoCPEStat += 1
        elif CRCtoCPECounter < CRCChance:
            pkt.accept()
    else:
        pkt.accept()
         
         
def cpe_stream_crc_broadcast():
    Socket = socket(AF_PACKET, SOCK_RAW)
    Socket.setsockopt(SOL_SOCKET, 43, 1)
    Socket.bind((EthtoUserstream, 0))
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(3, lambda pkt: cpe_send_crc_broadcast(pkt, Socket))
    try:
        queue.run()
    except:
        queue.unbind()
    
    
def cpe_send_crc_broadcast(pkt, Socket):
    global CRCtoUserCounter
    global CRCtoUserStat
    if CRC and CRCtoUser:
        CRCtoUserCounter += 1
        if CRCtoUserCounter >= CRCChance:
            packet = b'\xff\xff\xff\xff\xff\xff' + pkt.get_hw()[:-2] + b'\x08\x00' + pkt.get_payload() + b'\x09\x09\x09\x09'
            Socket.send(packet)
            pkt.drop()
            CRCtoUserCounter = 0
            CRCtoUserStat += 1
        elif CRCtoUserCounter < CRCChance:
            pkt.accept()
    else:
        pkt.accept()
        
        
def cpe_stream_crc_multicast():
    Socket = socket(AF_PACKET, SOCK_RAW)
    Socket.setsockopt(SOL_SOCKET, 43, 1)
    Socket.bind((EthtoUserstream, 0))
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(4, lambda pkt: cpe_send_crc_multicast(pkt, Socket))
    try:
        queue.run()
    except:
        queue.unbind()
    
    
def cpe_send_crc_multicast(pkt, Socket):
    global CRCtoUserCounter
    global CRCtoUserStat
    if CRC and CRCtoUser:
        CRCtoUserCounter += 1
        if CRCtoUserCounter >= CRCChance:
            dst_ip = pkt.get_payload()[16:20]
            if dst_ip[1] < 128:
                octet_4 = bytes([dst_ip[1]])
            else:
                octet_4 = bytes([dst_ip[1] - 0b10000000])
            packet = b'\x01\x00\x5e' + octet_4 + dst_ip[2:] + pkt.get_hw()[:-2] + b'\x08\x00' + pkt.get_payload() + b'\x09\x09\x09\x09'
            Socket.send(packet)
            pkt.drop()
            CRCtoUserCounter = 0
            CRCtoUserStat += 1
        elif CRCtoUserCounter < CRCChance:
            pkt.accept()
    else:
        pkt.accept()
        
        
def cpe_stream_crc_unicast():
    Socket = socket(AF_PACKET, SOCK_RAW)
    Socket.setsockopt(SOL_SOCKET, 43, 1)
    Socket.bind((EthtoUserstream, 0))
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(5, lambda pkt: cpe_send_crc_unicast(pkt, Socket))
    try:
        queue.run()
    except:
        queue.unbind()
    
    
def cpe_send_crc_unicast(pkt, Socket):
    global CRCtoUserCounter
    global CRCtoUserStat
    if CRC and CRCtoUser:
        CRCtoUserCounter += 1
        if CRCtoUserCounter >= CRCChance:
            packet = UserMACByte + pkt.get_hw()[:-2] + b'\x08\x00' + pkt.get_payload() + b'\x09\x09\x09\x09'
            Socket.send(packet)
            pkt.drop()
            CRCtoUserCounter = 0
            CRCtoUserStat += 1
        elif CRCtoUserCounter < CRCChance:
            pkt.accept()
    else:
        pkt.accept()

#===============CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=CRC=============

#===============DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=============

def user_stream_dly():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(6, lambda pkt: user_queue_add(pkt), buffer_size)
    try:
        queue.run()
    except:
        print('queue stopped')
        queue.unbind()


def user_queue_add(pkt):
    if Delay and DelaytoCPE:
        TXQueue.put(pkt) 
    elif OffTXDelay:
        TXQueue.put(pkt)
    else:
        pkt.accept()      
        
        
def user_send_dly():
    global DelaytoCPECounter
    while ScriptState: 
        pkt = TXQueue.get()
        if Delay and DelaytoCPE:
            DelaytoCPECounter += 1
            if DelaytoCPECounter >= DelayChance:
                sleep((DelayTime/1000-latency/1000) if (DelayTime/1000-latency/1000)>=0 else 0)
                DelaytoCPECounter = 0
        sleep(latency/1000)
        pkt.accept()
    
    
def cpe_stream_dly():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(7, lambda pkt: cpe_queue_add(pkt), buffer_size)
    try:
        queue.run()
    except:
        print('queue stopped')
        queue.unbind()


def cpe_queue_add(pkt):
    RXTime = time.time()
    if Delay and DelaytoUser:
        RXQueue.put(pkt) 
    elif OffRXDelay:
        RXQueue.put(pkt)
    else:
        pkt.accept()
            
        
def cpe_send_dly():
    global DelaytoUserCounter
    while ScriptState:
        pkt = RXQueue.get()
        if Delay and DelaytoUser:
            DelaytoUserCounter += 1
            if DelaytoUserCounter >= DelayChance:
                sleep((DelayTime/1000-latency/1000) if (DelayTime/1000-latency/1000)>=0 else 0)
                DelaytoUserCounter = 0
        sleep(latency/1000)
        pkt.accept()

#===============DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=DLY=============
    
TrafficState = False
ScriptState = True

CRCtoUserStat = 0
CRCtoCPEStat = 0

UserMAC = User_MAC.strip().lower()
UserMACByte = mac_to_byte(UserMAC.replace(':', ''))
CPEMAC = CPE_MAC.strip().lower()
CPEMACByte = mac_to_byte(CPEMAC.replace(':', ''))

CRCtoUserCounter = 0
CRCtoCPECounter = 0

DelaytoUserCounter = 0
DelaytoCPECounter = 0

CRC = EnableCRC
Delay = EnableDelay
Drop = EnableDrop

DelayChance = DelayChance

CRCtoUser = CRC_User
DelaytoUser = Delay_User
DroptoUser = Drop_User

CRCtoCPE = CRC_CPE
DelaytoCPE = Delay_CPE
DroptoCPE = Drop_CPE

iptables = False 
iptables_delay = False  

DroptoUserStatOld = 0
DroptoCPEStatOld = 0  

OffTXDelay = False
OffRXDelay = False

OffDelay = False


layout = [
    [sg.Text('CPE MAC: ', size=(9, 1)),
     sg.InputText(size=(20, 1), default_text=CPE_MAC, key='CPEMAC')
     ],
    [sg.Text('User MAC: ', size=(9, 1)),
     sg.InputText(size=(20, 1), default_text=User_MAC, key='UserMAC')
     ],
    [sg.Text("_" * 63, size=(63, 2))],
    [sg.Radio('Ошибки', "Type", size=(15, 3), key="CRC", default=EnableCRC), sg.Text('1 из ', size=(6, 1)),
     sg.InputText(size=(5, 1), default_text=CRCChance, key="CRCChance"), 
     sg.Text('пкт', size=(3, 1)), sg.Text('', size=(14, 1)), sg.Checkbox('К пользователю', key="CRCtoUserstream", default=CRC_User),
     sg.Checkbox('К CPE', default=CRC_CPE, key="CRCtoCPEstream")
     ],
    [sg.Radio('Задержки', "Type", size=(15, 3), key="Delay", default=EnableDelay), sg.Text('Время', size=(6, 1)),
     sg.InputText(size=(5, 1), default_text=DelayTime, key="DelayTime"),
     sg.Text('мс  1 из ', size=(7, 1)), sg.InputText(size=(5, 1), default_text=DelayChance, key="DelayChance"),
     sg.Text('пкт', size=(3, 1)), sg.Checkbox('К пользователю', key="DelaytoUserstream", default=Delay_User),
     sg.Checkbox('К CPE', default=Delay_CPE, key="DelaytoCPEstream")
     ],
    [sg.Radio('Дропы', "Type", size=(15, 3), key="Drop", default=EnableDrop), sg.Text(' ', size=(6, 1)),
     sg.InputText(size=(5, 1), default_text=DropChance, key="DropChance"), 
     sg.Text('%', size=(2, 1)), sg.Text('', size=(15, 1)), sg.Checkbox('К пользователю', key="DroptoUserstream", default=Drop_User),
     sg.Checkbox('К CPE', default=Drop_CPE, key="DroptoCPEstream")
     ],
    [sg.Radio('Выключть все', "Type", key="OffAll", default=True, size=(13, 1)), 
     sg.Text(f'Размер буфера {buffer_size} пакетов  '), sg.Text('Задержка пакетов в буфере'), sg.InputText(size=(5, 1), default_text=latency, key="Latency"), sg.Text('мс')],
    [sg.Button("Применить", size=(30, 1), key="ButtonApply"), sg.Button('Сбросить счетчики', size=(30, 1), key='Reset')],
]

window = sg.Window('Error Injector v2.5.2 (сложение задержек)', layout)

layout_meter = [
    [sg.Text('Заполнение буфера в сторону к пользователю: '), sg.Text('0', size=(5, 1), key='qlenUst'), sg.Text( 'Пакетов')],
    [sg.ProgressBar(buffer_size, key='UserQlen', size=(40,30))],
    [sg.Text('Заполнение буфера в сторону к CPE: '), sg.Text('0', size=(5, 1), key='qlenCst'), sg.Text( 'Пакетов')],
    [sg.ProgressBar(buffer_size, key='CPEQlen', size=(40,30))],
    [sg.Text('Дропов к Пользователю: ', size=(23, 1)), sg.Text('0', size=(20, 1), key='DroptoUser')],
    [sg.Text('Дропов к CPE: ', size=(23, 1)), sg.Text('0', size=(20, 1), key='DroptoCPE')],
    [sg.Text('Ошибок к Пользователю: ', size=(23, 1)), sg.Text(CRCtoUserStat, size=(20, 1), key='CRCtoUser')],
    [sg.Text('Ошибок к CPE: ', size=(23, 1)), sg.Text(CRCtoCPEStat, size=(20, 1), key='CRCtoCPE')],
]

window_meter = sg.Window('Статус', layout_meter)
window_meter.read(timeout=1)
def meter():
    global window_meter,buffer_size,DroptoUserStat,DroptoCPEStat,CRCtoUserStat,CRCtoCPEStat, RXQueue, TXQueue, OffRXDelay, OffTXDelay
    window_meter.Move(700, 600)
    while True:
        if not ScriptState: break
        UserQlen = RXQueue.qsize()
        CPEQlen = TXQueue.qsize()
        if OffDelay:
            OffRXDelay = True if UserQlen>1 else False
            OffTXDelay = True if CPEQlen>1 else False
        DroptoUserStat = int(subprocess.check_output(f"tc -s qdisc ls dev {EthtoUserstream} | grep dropped | awk '{{print $7}}'", shell=True, stderr=subprocess.STDOUT)[:-2]) - DroptoUserStatOld
        DroptoCPEStat = int(subprocess.check_output(f"tc -s qdisc ls dev {EthtoCPEstream} | grep dropped | awk '{{print $7}}'", shell=True, stderr=subprocess.STDOUT)[:-2]) - DroptoCPEStatOld
        window_meter['UserQlen'].UpdateBar(UserQlen, max=buffer_size)
        window_meter['CPEQlen'].UpdateBar(CPEQlen, max=buffer_size)
        window_meter['qlenUst'].Update(UserQlen)
        window_meter['qlenCst'].Update(CPEQlen)
        window_meter['DroptoUser'].Update(DroptoUserStat)
        window_meter['DroptoCPE'].Update(DroptoCPEStat)
        window_meter['CRCtoUser'].Update(CRCtoUserStat)
        window_meter['CRCtoCPE'].Update(CRCtoCPEStat)

   
try:   
    os.popen(f'tc qdisc add dev {EthtoUserstream} root netem limit {buffer_size}')
    os.popen(f'tc qdisc add dev {EthtoCPEstream} root netem limit {buffer_size}')

    MeterTask = Thread(target=meter)
    USBCTask = Thread(target=user_stream_crc_broadcast)
    CSBCTask = Thread(target=cpe_stream_crc_broadcast)
    USMCTask = Thread(target=user_stream_crc_multicast)
    CSMCTask = Thread(target=cpe_stream_crc_multicast)
    USUCTask = Thread(target=user_stream_crc_unicast)
    CSUCTask = Thread(target=cpe_stream_crc_unicast)
    USDDTask = Thread(target=user_send_dly)
    CSDDTask = Thread(target=cpe_send_dly)
    USDTask = Thread(target=user_stream_dly)
    CSDTask = Thread(target=cpe_stream_dly)
    
    # MainTask.start()
    MeterTask.start()
    USBCTask.start()
    CSBCTask.start()
    USMCTask.start()
    CSMCTask.start()
    USUCTask.start()
    CSUCTask.start()
    USDDTask.start()
    CSDDTask.start()
    USDTask.start()
    CSDTask.start()
    
    window.Move(700, 300)

    while True:  # The Event Loop
        event, values = window.read()
        if event in (None, 'Exit', 'Cancel'):
            ScriptState = False
            f = open('defconf', 'w')
            f.write(f'User MAC: {UserMAC}\n')
            f.write(f'CPE MAC: {CPEMAC}\n')
            f.write(f'User interface: {EthtoUserstream}\n')
            f.write(f'CPE interface: {EthtoCPEstream}\n')
            f.write(f'Buffer Size: {buffer_size}\n')
            f.close()
                
            os.popen(f'tc qdisc del dev {EthtoUserstream} root netem')
            os.popen(f'tc qdisc del dev {EthtoCPEstream} root netem')
            os.popen('iptables -w 5 -t mangle -F')
            pname = os.path.basename(sys.argv[0])
            os.system(f"pkill -f {pname}")
            break
            
        if event == "Reset":
            CRCtoUserStat = 0
            CRCtoCPEStat = 0
            DroptoUserStatOld = DroptoUserStat+DroptoUserStatOld
            DroptoCPEStatOld = DroptoCPEStat+DroptoCPEStatOld
            
        if event == "ButtonApply":
            CRCOld = CRC
            CRC = bool(values['CRC'])
            DelayOld = Delay
            Delay = bool(values['Delay'])
            DropOld = Drop
            Drop = bool(values['Drop'])

            CRCChance = int(values['CRCChance'])
            DelayTime = int(values['DelayTime'])
            DelayChance = int(values['DelayChance'])
            DropChance = float(values['DropChance'])

            CRCtoUser = bool(values['CRCtoUserstream'])
            DelaytoUserOld = DelaytoUser
            DelaytoUser = bool(values['DelaytoUserstream'])
            DroptoUserOld = DroptoUser
            DroptoUser = bool(values['DroptoUserstream'])

            CRCtoCPE = bool(values['CRCtoCPEstream'])
            DelaytoCPEOld = DelaytoCPE
            DelaytoCPE = bool(values['DelaytoCPEstream'])
            DroptoCPEOld = DroptoCPE
            DroptoCPE = bool(values['DroptoCPEstream'])
            
            OffAll = bool(values['OffAll'])
            
            #latency = float(values['Latency'])
                        
            os.popen(f'ifconfig {EthtoUserstream} txqueuelen {buffer_size}') 
            os.popen(f'ifconfig {EthtoCPEstream} txqueuelen {buffer_size}') 
            UserMACOld = UserMAC
            if len(values['UserMAC'].strip().lower().replace(':', '')) != 12:
                sg.popup('Неверно введен User MAC!\nДопускается AA:BB:CC:DD:EE:FF и AABBCCDDEEFF\n(регистр не учитывается)')
            else:
                if (":" in values['UserMAC'].strip().lower()) and (len(values['UserMAC'].strip().lower()) == 17):
                    UserMAC = values['UserMAC'].strip().lower()
                elif len(values['UserMAC'].strip().lower()) == 12:
                    octets = re.findall(r'\S\S', values['UserMAC'].strip().lower())
                    UserMAC = ':'.join(octets)
                else:
                    sg.popup('Неверно введен User MAC!\nДопускается AA:BB:CC:DD:EE:FF и AABBCCDDEEFF\n(регистр не учитывается)')
            UserMACByte = mac_to_byte(UserMAC.replace(':', ''))
            
            if len(values['CPEMAC'].strip().lower().replace(':', '')) != 12:
                sg.popup('Неверно введен CPE MAC!\nДопускается AA:BB:CC:DD:EE:FF и AABBCCDDEEFF\n(регистр не учитывается)')
            else:
                if (":" in values['CPEMAC'].strip().lower()) and (len(values['CPEMAC'].strip().lower()) == 17):
                    CPEMAC = values['CPEMAC'].strip().lower()
                elif len(values['CPEMAC'].strip().lower()) == 12:
                    octets = re.findall(r'\S\S', values['CPEMAC'].strip().lower())
                    CPEMAC = ':'.join(octets)
                else:
                    sg.popup('Неверно введен CPE MAC!\nДопускается AA:BB:CC:DD:EE:FF и AABBCCDDEEFF\n(регистр не учитывается)')
            CPEMACByte = mac_to_byte(CPEMAC.replace(':', ''))
            
            if Delay != DelayOld:
                if Delay and not iptables_delay:
#                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type broadcast -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 6')
#                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type multicast -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 6')
#                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type unicast -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 6')
#                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type broadcast -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 7')
#                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type multicast -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 7')
#                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type unicast -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 7')
                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 6')
                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 7')
                    sleep(1)
                    iptables_delay = True
                elif Delay:
                    pass
                else:
                    OffDelay = True
                    while OffRXDelay or OffTXDelay:
                        pass
                    OffDelay = False
                    os.popen(f'iptables -w 5 -t mangle -F')
                    iptables_delay = False
                    
            if Drop != DropOld:
                if not Drop:
                    os.popen(f'tc qdisc change dev {EthtoUserstream} root netem limit {buffer_size} loss 0%')
                    os.popen(f'tc qdisc change dev {EthtoCPEstream} root netem limit {buffer_size} loss 0%')
                else:
                    os.popen(f'iptables -w 5 -t mangle -F')
                    if DroptoUser:
                        os.popen(f'tc qdisc change dev {EthtoUserstream} root netem limit {buffer_size} loss {DropChance}%')
                    if DroptoCPE:
                        os.popen(f'tc qdisc change dev {EthtoCPEstream} root netem limit {buffer_size} loss {DropChance}%')
                    if DroptoUserOld and not DroptoUser:
                        os.popen(f'tc qdisc change dev {EthtoUserstream} root netem limit {buffer_size} loss 0%')
                    if DroptoCPEOld and not DroptoCPE:
                        os.popen(f'tc qdisc change dev {EthtoCPEstream} root netem limit {buffer_size} loss 0%')
            if Drop and DropOld:
                if Drop:
                    if DroptoUser:
                        os.popen(f'tc qdisc change dev {EthtoUserstream} root netem limit {buffer_size} loss {DropChance}%')
                    if DroptoCPE:
                        os.popen(f'tc qdisc change dev {EthtoCPEstream} root netem limit {buffer_size} loss {DropChance}%')
                    if DroptoUserOld and not DroptoUser:
                        os.popen(f'tc qdisc change dev {EthtoUserstream} root netem limit {buffer_size} loss 0%')
                    if DroptoCPEOld and not DroptoCPE:
                        os.popen(f'tc qdisc change dev {EthtoCPEstream} root netem limit {buffer_size} loss 0%')
                else:
                    os.popen(f'tc qdisc change dev {EthtoUserstream} root netem limit {buffer_size} loss 0%')
                    os.popen(f'tc qdisc change dev {EthtoCPEstream} root netem limit {buffer_size} loss 0%')
                    
            if CRC != CRCOld:
                if CRC and not iptables:
                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type broadcast -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 0')
                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type multicast -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 1')
                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type unicast -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 2')
                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type broadcast -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 3')
                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type multicast -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 4')
                    os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type unicast -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 5')
                    sleep(1)
                    iptables = True
                elif CRC:
                    pass
                else:
                    os.popen(f'iptables -w 5 -t mangle -F')
                    iptables = False
                    
            if (UserMAC != UserMACOld) and CRC:
                os.popen(f'iptables -w 5 -t mangle -F')
                os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type broadcast -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 0')
                os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type multicast -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 1')
                os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type unicast -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 2')
                os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type broadcast -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 3')
                os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type multicast -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 4')
                os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type unicast -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 5')
            if (UserMAC != UserMACOld) and Delay:
#                os.popen(f'iptables -w 5 -t mangle -F')
#                os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type broadcast -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 6')
#                os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type multicast -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 6')
#                os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type unicast -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 6')
#                os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type broadcast -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 7')
#                os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type multicast -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 7')
#                os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m pkttype --pkt-type unicast -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 7')
                 os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m mac --mac-source {User_MAC} -j NFQUEUE --queue-num 6')
                 os.popen(f'iptables -w 5 -t mangle -I PREROUTING -i {iface_br} -m mac ! --mac-source {User_MAC} -j NFQUEUE --queue-num 7')
                                    
    # MainTask.join()
    MeterTask.join()
    USBCTask.join()
    CSBCTask.join()
    USMCTask.join()
    CSMCTask.join()
    USUCTask.join()
    CSUCTask.join()
    USDDTask.join()
    CSDDTask.join()
    USDTask.join()
    CSDTask.join()
    
except KeyboardInterrupt:
    os.popen(f'tc qdisc del dev {EthtoUserstream} root netem')
    os.popen(f'tc qdisc del dev {EthtoCPEstream} root netem')
    os.popen('iptables -w 5 -t mangle -F')
    pname = os.path.basename(sys.argv[0])
    os.system(f"pkill -f {pname}")
    
