name_script="set_interface_ip.sh"

name_int_pump="enx00e04c36418d" #ex : "eth0"
name_int_sensor_1="enx00e04c360077"
name_int_sensor_2="enx00e04c3642c5"

subnet_pump="192.168.20.10"
subnet_sensor_1="192.168.110.10"
subnet_sensor_2="192.168.10.10"


#pump:
sudo sh  "$name_script" "$name_int_pump" "$subnet_pump"
#sensor 1
sudo sh  "$name_script" "$name_int_sensor_1" "$subnet_sensor_1"
#sensor 2
sudo sh  "$name_script" "$name_int_sensor_2" "$subnet_sensor_2"

