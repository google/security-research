#!/bin/bash

clear

echo -n "Input DST_BIND_HANDLE: "
read DST_BIND_HANDLE

echo -n "Input DST_BIND_UUID: "
read DST_BIND_UUID

echo -e "\n[%%] Writing migration destination decryption key..."
echo "mig-td: python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000010 0xde -1"
python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000010 0xde -1
echo "mig-td: python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000011 0x7e -1"
python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000011 0x7e -1
echo "mig-td: python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000012 0xc7 -1"
python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000012 0xc7 -1
echo "mig-td: python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000013 0xed -1"
python tdg_servtd_wr.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000013 0xed -1

echo -e "\n[%%] Printing migration destination decryption key..."
python tdg_servtd_rd.py $DST_BIND_HANDLE $DST_BIND_UUID 0x9810000300000010 --count 4

echo -e "\n[+] Migration TD key assignment completed."