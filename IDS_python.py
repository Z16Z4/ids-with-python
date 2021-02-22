from scapy.all import *
from datetime import datetime
import requests
import os.system

class ids:
    __flagsTCP = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
        }

    ip_cnt_TCP = {}               

    __THRESH=1000               
    # while True:
      #  try:
       #     requests.get('https://duckduckgo.com/').status_code
        #    break
        #except:
         #   time.sleep(5)
          #  pass
            
                
    
    def sniffPackets(self,packet):
        if packet.haslayer(IP):
            pckt_src=packet[IP].src
            pckt_dst=packet[IP].dst
            print("IP Packet: %s  ==>  %s  , %s"%(pckt_src,pckt_dst,str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))))

        if packet.haslayer(TCP):
            src_port=packet.sport
            dst_port=packet.dport
            print(", Port: %s --> %s, "%(src_port,dst_port))
            print([type(self).__flagsTCP[x] for x in packet.sprintf('%TCP.flags%')])
            self.detect_TCPflood(packet)
        else:
            print()


    def detect_TCPflood(self,packet):
        if packet.haslayer(TCP):
            pckt_src=packet[IP].src
            pckt_dst=packet[IP].dst
            stream = pckt_src + ':' + pckt_dst

            if stream in type(self).ip_cnt_TCP:
                type(self).ip_cnt_TCP[stream] += 1
            else:
                type(self).ip_cnt_TCP[stream] = 1

            for stream in type(self).ip_cnt_TCP:
                pckts_sent = type(self).ip_cnt_TCP[stream]
                if pckts_sent > type(self).__THRESH:
                    src = stream.split(':')[0]
                    dst = stream.split(':')[1]
                    print("Excessive packets from: %s --> %s, This has been logged in /Documents/IDSlogs." %(src,dst))
            os.system('cat /var/log/auth.log | grep "ssh" >> test')
            os.system('cat test')

if __name__ == '__main__':
    print("Dissertation IDS with Python")
    sniff(filter="ip",iface="wlan0",prn=ids().sniffPackets)
    if cat auth.log | grep "SSH" returns ...:print("SSH attempt detected")
