#!/bin/bash

show_help() {
  echo "Usage: $0 <dst_td_name> <mig_td_name> <hkid>"
  echo ""
  echo "Create a destination TD, bind it to a migration TD, and create a migration stream."
  echo "Before running ensure that a migration TD has been added via 'python tdxamine.py add_td_by_pid `pgrep -f -o qemu` mig_td'"
  echo ""
  echo "Arguments:"
  echo "  <dst_td_name>  : Name of the destination TD to create."
  echo "  <mig_td_name>  : Name of the migration TD to bind and create a stream for."
  echo "  <hkid>         : Host key identifier to use for the destination TD."
  echo ""
  echo "Example:"
  echo "  $0 dst_td mig_td 73"
}

if [ "$#" -ne 3 ]; then
  echo "Error: Incorrect number of arguments provided."
  show_help
  exit 1
fi

DST_TD_NAME=$1
MIG_TD_NAME=$2
HKID=$3

echo "Creating destination TD..."
echo "python tdh_mng_create.py $DST_TD_NAME --hkid $HKID"
python tdh_mng_create.py $DST_TD_NAME --hkid $HKID

DST_TD_PA=$(python tdxamine.py print_tdr_pa_from_name $DST_TD_NAME)

echo "Configuring destination TD key..."
echo "python tdh_mng_key_config.py $DST_TD_PA"
python tdh_mng_key_config.py $DST_TD_PA

echo "Allocating TDCX pages for the destiantion TD..."
echo "python tdh_mng_addcx.py $DST_TD_PA"
python tdh_mng_addcx.py $DST_TD_PA

MIG_TD_PA=$(python tdxamine.py print_tdr_pa_from_name $MIG_TD_NAME)

echo "Binding migration TD to the destination TD..."
echo "python tdh_servtd_bind.py $DST_TD_PA $MIG_TD_PA"
python tdh_servtd_bind.py $DST_TD_PA $MIG_TD_PA

echo "Creating migration stream..."
echo "python tdh_mig_stream_create.py $DST_TD_PA"
python tdh_mig_stream_create.py $DST_TD_PA

echo "Instruct the migration TD to set the destination TD decryption key..."
