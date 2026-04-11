#!/bin/bash

clear

echo -n "Input SRC_BIND_HANDLE: "
read SRC_BIND_HANDLE

echo -n "Input SRC_BIND_UUID: "
read SRC_BIND_UUID

echo -n "Input DST_BIND_HANDLE: "
read DST_BIND_HANDLE

echo -n "Input DST_BIND_UUID: "
read DST_BIND_UUID

echo -e "\n[%%] Printing migration source encryption key..."
echo "mig-td: python tdg_servtd_rd.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x9810000300000018 --count=4"
python tdg_servtd_rd.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x9810000300000018 --count=4

SRC_KEY0=$(python tdg_servtd_rd.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x9810000300000018 | sed 's/.*contents: \(.*\)/\1/')
SRC_KEY1=$(python tdg_servtd_rd.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x9810000300000019 | sed 's/.*contents: \(.*\)/\1/')
SRC_KEY2=$(python tdg_servtd_rd.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x981000030000001a | sed 's/.*contents: \(.*\)/\1/')
SRC_KEY3=$(python tdg_servtd_rd.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x981000030000001b | sed 's/.*contents: \(.*\)/\1/')

echo -e "\n[%%] Printing migration destination encryption key..."
echo "mig-td: python tdg_servtd_rd.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000018 --count=4"
python tdg_servtd_rd.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000018 --count=4

DST_KEY0=$(python tdg_servtd_rd.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000018 | sed 's/.*contents: \(.*\)/\1/')
DST_KEY1=$(python tdg_servtd_rd.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000019 | sed 's/.*contents: \(.*\)/\1/')
DST_KEY2=$(python tdg_servtd_rd.py $DST_BIND_HANDLE $DST_BIND_UUID 0x981000030000001a | sed 's/.*contents: \(.*\)/\1/')
DST_KEY3=$(python tdg_servtd_rd.py $DST_BIND_HANDLE $DST_BIND_UUID 0x981000030000001b | sed 's/.*contents: \(.*\)/\1/')

sleep 1
echo -e "\n[%%] Writing migration source decryption key..."
echo "mig-td: python tdg_servtd_wr.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x9810000300000010 -1 $DST_KEY0"
python tdg_servtd_wr.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x9810000300000010 -1 $DST_KEY0
echo "mig-td: python tdg_servtd_wr.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x9810000300000011 -1 $DST_KEY1"
python tdg_servtd_wr.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x9810000300000011 -1 $DST_KEY1
echo "mig-td: python tdg_servtd_wr.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x9810000300000012 -1 $DST_KEY2"
python tdg_servtd_wr.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x9810000300000012 -1 $DST_KEY2
echo "mig-td: python tdg_servtd_wr.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x9810000300000013 -1 $DST_KEY3"
python tdg_servtd_wr.py $SRC_BIND_HANDLE $SRC_BIND_UUID 0x9810000300000013 -1 $DST_KEY3

sleep 1
echo -e "\n[%%] Writing migration destination decryption key..."
echo "mig-td: python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000010 -1 $SRC_KEY0"
python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000010 $SRC_KEY0 -1
echo "mig-td: python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000011 -1 $SRC_KEY1"
python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000011 $SRC_KEY1 -1
echo "mig-td: python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000012 -1 $SRC_KEY2"
python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000012 $SRC_KEY2 -1
echo "mig-td: python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000013 -1 $SRC_KEY3"
python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000013 $SRC_KEY3 -1

echo -e "\n[+] Migration TD keys exchange completed."