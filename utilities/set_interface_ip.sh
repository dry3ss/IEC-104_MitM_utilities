
if [ "$#" -eq "2" ];then
	sudo ifconfig "$1" "$2" netmask 255.255.255.0
else
	echo "usage: $0 name_interface subnet"
fi 

