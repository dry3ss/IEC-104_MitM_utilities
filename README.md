# IEC-104_MitM_utilities
A Man in the Middle (MitM) attack using Scapy to replace 2 bytes worth of data in the payload of an IEC/104 ASDU.
Designed to keep the pump of project : https://github.com/dry3ss/IEC-608670-5-104-Grovepi from stopping.
Also contains small utility scripts used to quickly setup the different interfaces used during https://github.com/dry3ss/IEC-608670-5-104-Grovepi

## How to use :

**Utility shell scripts:**
1. Only modify utilities/setup_pump_sensor_interfaces.sh (not set_interface_ip.sh) to change the various interfaces names (ie "eth0") and interfaces IP address (eg "192.168.1.1").
2. Launch it from *inside the utilities folder* (eg sh setup_pump_sensor_interfaces.sh from inside utilities)

**Attack python scripts:**
1. Modify **both** scripts to change the IP, interface, and potentially MAC addresses. The first script (1_ARP_poisoning.py) will automatically find the MAC address from the IP through an ARP exchange, however, the second one (2_mitm_modify_packets_IEC_104.py) **will not** (as is), two very small modifications would allow this (look at line 40->44). 
2. Launch 1_ARP_poisoning.py first (eg python 1_ARP_poisoning.py) in one shell window.
3. Launch 2_mitm_modify_packets_IEC_104.py (eg python 2_mitm_modify_packets_IEC_104.py) in *another* shell window.
4. Setup everything that needs to be setup regarding the controler, the pump and the sensors.
5. When you want to effectively start the attack and keep the pump from stoping (forcing it forward actually) press ctrl-c in the shell window hosting 2_mitm_modify_packets_IEC_104.py, each and everytime a packet is modified, the whole TCP payload (so the APDU+ASDU) before and after modification will be printed.
6. When you want to resume normal operations, press ctrl-c again in the shell window hosting 2_mitm_modify_packets_IEC_104.py

