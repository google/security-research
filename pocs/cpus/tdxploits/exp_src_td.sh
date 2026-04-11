#!/bin/bash

show_help() {
  echo "Usage: $0 <src_td_name>"
  echo ""
  echo "Export a source TD's state to a set of files."
  echo "Before running ensure that:"
  echo "  1. Source TD was created with the MIGRATE flag set"
  echo "  2. Source TD has been added via 'python tdxamine.py add_td_by_pid `pgrep -f -o qemu` src_td'"
  echo "  3. Migration TD has been bound to the source TD."
  echo "  4. Migration TD has set the MIG_DEC_KEY for the source TD."
  echo ""
  echo "Arguments:"
  echo "  <src_td_name>  : Name of the source TD to export."
  echo ""
  echo "Example:"
  echo "  $0 src_td"
}

if [ "$#" -ne 1 ]; then
  echo "Error: Incorrect number of arguments provided."
  show_help
  exit 1
fi

SRC_TD_NAME=$1

SRC_TD_PA=$(python tdxamine.py print_tdr_pa_from_name src_td)

echo "Creating migration stream..."
echo "python tdh_mig_stream_create.py $SRC_TD_PA"
python tdh_mig_stream_create.py $SRC_TD_PA

echo "Exporting source TD immutable state to immutable.export.mbmd and immutable.export.data..."
echo "python tdh_export_state_immutable.py $SRC_TD_PA immutable.export.mbmd immutable.export.data"
python tdh_export_state_immutable.py $SRC_TD_PA immutable.export.mbmd immutable.export.data

echo "Pausing source TD..."
echo "python tdh_export_pause.py $SRC_TD_PA"
python tdh_export_pause.py $SRC_TD_PA

echo "Exporting source TD td state to td.export.mbmd and td.export.data..."
echo "python tdh_export_state_td.py $SRC_TD_PA td.export.mbmd td.export.data"
python tdh_export_state_td.py $SRC_TD_PA td.export.mbmd td.export.data

echo "Exporting source TD vp0 state to vp0.export.mbmd and vp0.export.data..."
echo "python tdh_export_state_vp.py $SRC_TD_PA 0 vp0.export.mbmd vp0.export.data"
python tdh_export_state_vp.py $SRC_TD_PA 0 vp0.export.mbmd vp0.export.data
