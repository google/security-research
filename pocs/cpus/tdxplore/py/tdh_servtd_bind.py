from argparse import ArgumentParser

from tdxamine import State, TdData
from tdxtend import SERVTD_TYPE_MIGTD, TdxErrorCode, TdxStatus, Tdxtend
from gateway import Gateway


def main():
  parser = ArgumentParser(description="tdh_servtd_bind")

  parser.add_argument(
      "tgt_tdr", type=lambda x: int(x, 0), help="TDR address of the target TD"
  )

  parser.add_argument(
      "serv_tdr", type=lambda x: int(x, 0), help="TDR address of the service TD"
  )

  parser.add_argument(
      "--index",
      default=0,
      type=str,
      help="Index (slot number) in the target TD's service TD binding table",
  )

  parser.add_argument(
      "--servtd_type",
      type=lambda x: int(x, 0),
      default=SERVTD_TYPE_MIGTD,
      help="Expected service TD type",
  )

  parser.add_argument(
      "--servtd_attributes",
      default=0,
      type=lambda x: int(x, 0),
      help="Expected service TD attributes",
  )

  parser.add_argument(
      "--state",
      type=str,
      default="state.pickle",
      help="State to load",
  )

  args = parser.parse_args()

  gateway = Gateway()

  state = State(args.state)

  serv_td = state.get_td_by_tdr_pa(args.serv_tdr)
  tgt_td = state.get_td_by_tdr_pa(args.tgt_tdr)

  tdxtend = Tdxtend(0, gateway)

  rc, bind_handle, uuid0, uuid1, uuid2, uuid3 = (
      tdxtend.call_tdh_servtd_bind_leaf(
          tgt_td.tdr_pa,
          serv_td.tdr_pa,
          args.index,
          args.servtd_type,
          args.servtd_attributes,
      )
  )

  if rc != TdxErrorCode.TDX_SUCCESS.value:
    print(f"TDX STATUS: {TdxStatus(rc)}")
  else:
    print(f"binding_handle: {hex(bind_handle)}")
    print(f"uuid: {uuid0:x}-{uuid1:x}-{uuid2:x}-{uuid3:x}")

    if bind_handle not in serv_td.bind_handles:
      serv_td.bind_handles.append(bind_handle)

    bind_uuid = f"{uuid0:x}-{uuid1:x}-{uuid2:x}-{uuid3:x}"
    if bind_uuid not in serv_td.bind_uuids:
      serv_td.bind_uuids.append(bind_uuid)

    state.save(args.state)


if __name__ == "__main__":
  main()
