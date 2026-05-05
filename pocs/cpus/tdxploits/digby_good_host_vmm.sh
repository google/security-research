#!/bin/bash

SRC_TD_NAME="src_td"
DST_TD_NAME="dst_td"
MIG_TD_NAME="mig_td"

rm state.pickle
clear

echo -n "Input DST_TD_HKID: "
read DST_TD_HKID

sleep 1
echo -e "\n[%%] Adding source TD to the state..."
echo "host-vmm: python tdxamine.py add_td_by_pid `pgrep -f -n qemu` $SRC_TD_NAME"
python tdxamine.py add_td_by_pid `pgrep -f -n qemu` $SRC_TD_NAME

SRC_TD_PA=$(python tdxamine.py print_tdr_pa_from_name $SRC_TD_NAME)

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
echo -e "\n[%%] Creating source migration stream..."
echo "host-vmm: python tdh_mig_stream_create.py $SRC_TD_PA"
python tdh_mig_stream_create.py $SRC_TD_PA

sleep 1
echo -e "\n[%%] Creating destination migration stream..."
echo "host-vmm: python tdh_mig_stream_create.py $DST_TD_PA"
python tdh_mig_stream_create.py $DST_TD_PA

sleep 1
echo -e "\n[%%] Print migration TD binding information for the source TD..."
echo "host-vmm: python tdh_servtd_bind.py $SRC_TD_PA $MIG_TD_PA"
python tdh_servtd_bind.py $SRC_TD_PA $MIG_TD_PA

sleep 1
echo -e "\n[%%] Print source ATTRIBUTES (0x30000000 is migratable)..."
echo "host-vmm: python tdh_md_rd.py $DST_TD_PA td 0x1110000300000000"
python tdh_md_rd.py $SRC_TD_PA td 0x1110000300000000

echo -e "\n[!] Instruct the migration TD to perform keys exchange (press any key to continue)..."
read pause

sleep 1
echo "[%%] Exporting source TD immutable state to immutable.expt.mbmd and immutable.data..."
echo "host-vmm: python tdh_export_state_immutable.py $SRC_TD_PA immutable.mbmd immutable.data"
python tdh_export_state_immutable.py $SRC_TD_PA immutable.mbmd immutable.data

sleep 1
echo -e "\n[%%] Pausing source TD..."
echo "host-vmm: python tdh_export_pause.py $SRC_TD_PA"
python tdh_export_pause.py $SRC_TD_PA

sleep 1
echo -e "\n[%%] Exporting source TD td state to td.mbmd and td.data..."
echo "host-vmm: python tdh_export_state_td.py $SRC_TD_PA td.mbmd td.data"
python tdh_export_state_td.py $SRC_TD_PA td.mbmd td.data

sleep 1
echo -e "\n[%%] Exporting source TD vp0 state to vp0.mbmd and vp0.data..."
echo "host-vmm: python tdh_export_state_vp.py $SRC_TD_PA 0 vp0.mbmd vp0.data"
python tdh_export_state_vp.py $SRC_TD_PA 0 vp0.mbmd vp0.data

echo -e "\n[+] Target TD export completed."

