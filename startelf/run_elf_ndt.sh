#!/bin/bash

HOST="c10"
INTERFACE="eno2"
GATEWAY="149.43.152.1"
XHOME="/home/jsommers/"
TSTAMP=`date +%Y%m%d%H%M%S`

euid=`id -u`
if [[ $euid != "0" ]]; then
    echo "Gotta be root"
    exit
fi


rm -f ndthost.sh
pushd $XHOME/tput_someta
python3 getndt.py -c GB > ndthost.sh
NDTHOST=`head -1 ndthost.sh | awk '{ print $2 }'`
if [ -z $NDTHOST ]; then
	echo "No NDT hosts"
	exit;
else
	echo $NDTHOST
fi

/usr/bin/python3 ${XHOME}/ebpf_project/ELF/elfprobe.py -a ndt7-client -q -l -f ${HOST}_elf_ndt_${TSTAMP} -i ${INTERFACE} -p 10 ${NDTHOST} &
ebpfpid=$!
echo 'sleeping 5 sec; waiting for ELF startup'
sleep 5

${XHOME}/go/bin/someta -y someta_ndt.yaml

sleep 2

kill -INT $ebpfpid
echo "all done!"
sleep 1
mv c10* ${XHOME}/tput_data
popd
