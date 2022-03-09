#!/bin/bash

HOST="in"
TARGET="out"
INTERFACE="enp5s0f0" #this is all setup 
TSTAMP=`date +%Y%m%d%H%M%S`

euid=`id -u`
if [[ $euid != "0" ]]; then
    echo "Gotta be root" #checks for root access
    exit
fi

python3 ~/ELF/elfprobe.py -a iperf -q -l -f ${HOST}_elf_iperf_${TSTAMP} -i ${INTERFACE} -p 10 ${TARGET} &
ebpfpid=$!
echo 'sleeping 5 sec; waiting for ELF startup'
sleep 5

~/local/go/bin/someta -y someta_iperf.yaml

sleep 2

kill -INT $ebpfpid
echo "all done!"
sleep 1
