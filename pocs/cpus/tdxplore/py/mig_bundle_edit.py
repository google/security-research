import argparse
import ast
import binascii
import re
from typing import Any

import structpp
import struct
from tinny import Tinny
from gateway import FOUR_KILOBYTES
from gateway import Gateway


literal_eval = ast.literal_eval
ArgumentParser = argparse.ArgumentParser
_TD_LIST_HEADER_FORMAT = "<H{list_buff_size}H{num_sequences}I{reserved}"
_TD_LIST_HEADER_FORMAT_OLD = "<HHI"

_TD_SEQUENCE_HEADER_FORMAT = (
    "<I{field_code: 24, reserved: 8}I{element_size_code: 2,"
    " last_element_in_field: 4, last_field_in_sequence: 9, reserved_1: 3,"
    " inc_size: 1, write_mask_valid: 1, context_code: 3, reserved_2: 1,"
    " class_code: 6, reserved_3: 1, ignored: 1}"
)


class TdSequence:
  header: Any
  fields: list[list[int]]


class TdBuffer:
  list_header: Any
  sequences: list[TdSequence]


class TdMetadata:
  """TD metadata helper class."""

  def __init__(self, input_file: str = None):
    self.raw_buffers = []
    self.buffers = []
    self.total_sequences = []
    if not input_file:
      return
    with open(input_file, "rb") as f:
      while True:
        buffer = f.read(FOUR_KILOBYTES)

        if not buffer:
          break

        self.raw_buffers.append(buffer)

    for buffer_idx, buffer in enumerate(self.raw_buffers):
      idx = 0
      try:
        list_header = structpp.unpack(
            _TD_LIST_HEADER_FORMAT, buffer[idx : idx + 8]
        )
      except struct.error:
        print(f"ERROR: Read went OOB at buffer[{buffer_idx}]")
        break
      #print(
      #    f"[{buffer_idx}] list_buff_size: {list_header.list_buff_size},"
      #    f" num_sequences: {list_header.num_sequences}"
      #)
      idx += 8
      sequences = []
      for seq_idx in range(list_header.num_sequences):
        try:
          seq_hdr = structpp.unpack(
              _TD_SEQUENCE_HEADER_FORMAT,
              buffer[idx : idx + 8],
          )
        except struct.error:
          print(f"ERROR: Read went OOB at buffer={buffer_idx}, sequence={seq_idx}")
          break
        idx += 8
        if False:
          print(
              f"[Sequence {seq_idx}] field_code: {seq_hdr.field_code:02x},"
              f" element_size_code: {seq_hdr.element_size_code},"
              f" last_element_in_field: {seq_hdr.last_element_in_field},"
              f" last_field_in_sequence: {seq_hdr.last_field_in_sequence},"
              f" inc_size: {seq_hdr.inc_size}, write_mask_valid:"
              f" {seq_hdr.write_mask_valid}, context: {seq_hdr.context_code},"
              f" class_code: {seq_hdr.class_code}"
          )
        sequence = TdSequence()
        sequence.header = seq_hdr
        sequence.fields = []
        for field_idx in range(seq_hdr.last_field_in_sequence + 1):
          elements = []
          for element_idx in range(seq_hdr.last_element_in_field + 1):
            if False:
              print(f"  field {field_idx}, element {element_idx}")
            try:
              value = structpp.unpack("<Q", buffer[idx : idx + 8])[0]
            except struct.error:
              print(f"ERROR: Read went OOB at buffer={buffer_idx}, sequence={seq_idx}, field={field_idx}, element={element_idx}")
              break
            idx += 8
            elements.append(value)
          sequence.fields.append(elements)
        sequences.append(sequence)
        # Also add to the total sequences list so we can rebuild the buffers.
        self.total_sequences.append(sequence)
      td_buffer = TdBuffer()
      td_buffer.list_header = list_header
      td_buffer.sequences = sequences
      self.buffers.append(td_buffer)

  def add_buffer(self, list_buff_size: int = 8, num_sequences: int = 0):
    """Adds a new buffer to the metadata."""
    td_buffer = TdBuffer()
    tmp = structpp.pack(
        _TD_LIST_HEADER_FORMAT, list_buff_size, num_sequences, 0
    )
    td_buffer.list_header = structpp.unpack(_TD_LIST_HEADER_FORMAT, tmp)
    td_buffer.sequences = []
    self.buffers.append(td_buffer)

  def append_sequence(
      self,
      buffer_idx,
      field_code,
      element_size_code,
      last_element_in_field,
      last_field_in_sequence,
      inc_size,
      write_mask_valid,
      context_code,
      class_code,
  ):
    """Adds a new sequence to the metadata."""
    if buffer_idx > len(self.buffers):
      raise IndexError(f"Buffer {buffer_idx} not found")
    tmp = structpp.pack(
        _TD_SEQUENCE_HEADER_FORMAT,
        field_code,
        0,
        element_size_code,
        last_element_in_field,
        last_field_in_sequence,
        0,
        inc_size,
        write_mask_valid,
        context_code,
        0,
        class_code,
        0,
        0,
    )
    sequence = TdSequence()
    sequence.header = structpp.unpack(_TD_SEQUENCE_HEADER_FORMAT, tmp)
    sequence.fields = [
        [0 for _ in range(last_field_in_sequence + 1)]
        for _ in range(last_element_in_field + 1)
    ]
    self.buffers[buffer_idx].sequences.append(sequence)
    new_cnt = self.buffers[buffer_idx].list_header.num_sequences + 1
    self.buffers[buffer_idx].list_header = self.buffers[
        buffer_idx
    ].list_header._replace(num_sequences=new_cnt)
    self.total_sequences.append(sequence)

  def _make_empty_sequence(
      self,
      field_code,
      element_size_code,
      last_element_in_field,
      last_field_in_sequence,
      inc_size,
      write_mask_valid,
      context_code,
      class_code,
      ignored
  ) -> TdSequence:
    tmp = structpp.pack(
        _TD_SEQUENCE_HEADER_FORMAT,
        field_code,
        0,
        element_size_code,
        last_element_in_field,
        last_field_in_sequence,
        0,
        inc_size,
        write_mask_valid,
        context_code,
        0,
        class_code,
        0,
        ignored,
    )
    sequence = TdSequence()
    sequence.header = structpp.unpack(_TD_SEQUENCE_HEADER_FORMAT, tmp)
    sequence.fields = [
        [0 for _ in range(last_field_in_sequence + 1)]
        for _ in range(last_element_in_field + 1)
    ]
    return sequence

  def insert_sequence(self, index: int, identifier: int, elements: list[int]):
    ignored = (identifier >> 63) & 0x1
    class_code = (identifier >> 56) & 0x3F
    context_code = (identifier >> 52) & 0x3
    write_mask_valid = (identifier >> 51) & 0x1
    inc_size = (identifier >> 50) & 0x1
    last_field_in_sequence = (identifier >> 38) & 0x1FF
    last_element_in_field = (identifier >> 34) & 0xF
    element_size_code = (identifier >> 32) & 0x3
    field_code = identifier & 0xFFFFFFFF
    #max_total_elements = (last_field_in_sequence + 1) * (last_element_in_field + 1)
    #if len(elements) > max_total_elements:
    #  print(f"Truncating elements to {max_total_elements} elements.")
    #  elements = elements[:max_total_elements]

    if len(elements) - 1 > 0x1FF:
      raise ValueError(f"Too many elements: {len(elements) - 1} > 0x1FF")
    if index > len(self.total_sequences):
      raise IndexError(f"Index {index} outside of range [0, {len(self.total_sequences)}]")
    sequence = self._make_empty_sequence(field_code, element_size_code,
                                         0,  # last_field_in_sequence
                                         len(elements) - 1,  # last_element_in_field
                                         inc_size,
                                         write_mask_valid, context_code,
                                         class_code, ignored)
    sequence.fields[0] = elements
    self.total_sequences.insert(index, sequence)

  def dump(self, id_target: int = -1):
    """Dumps the TD metadata."""
    for buffer_idx, buffer in enumerate(self.raw_buffers):
      print(f"=== Buffer {buffer_idx} ===")
      idx = 0
      list_header = structpp.unpack(
          "<H{list_buff_size}H{num_sequences}I{reserved}", buffer[idx : idx + 8]
      )
      idx += 8
      print(
          f"list_buff_size: {list_header.list_buff_size}, num_sequences:"
          f" {list_header.num_sequences}"
      )
      for seq_idx in range(list_header.num_sequences):
        if buffer_idx == 0 and seq_idx == 0:
          print(f"seq_hdr: {binascii.hexlify(buffer[idx : idx + 8])}")
        seq_hdr = structpp.unpack(
            _TD_SEQUENCE_HEADER_FORMAT,
            buffer[idx : idx + 8],
        )
        idx += 8
        # context = {0: "global", 1: "TD", 2: "VP"}[seq_hdr.context_code]
        identifier = (
            seq_hdr.ignored << 63
            | seq_hdr.class_code << 56
            | seq_hdr.context_code << 52
            | seq_hdr.write_mask_valid << 51
            | seq_hdr.inc_size << 50
            | seq_hdr.element_size_code << 32
            | seq_hdr.field_code
        )
        if id_target != -1 and identifier != id_target:
          continue
        print(
            f"[Sequence {seq_idx}] field_code: {seq_hdr.field_code:02x},"
            f" element_size_code: {seq_hdr.element_size_code},"
            f" last_element_in_field: {seq_hdr.last_element_in_field},"
            f" last_field_in_sequence: {seq_hdr.last_field_in_sequence},"
            f" inc_size: {seq_hdr.inc_size}, write_mask_valid:"
            f" {seq_hdr.write_mask_valid}, context: {seq_hdr.context_code},"
            f" class_code: {seq_hdr.class_code},"
            f" ignored: {seq_hdr.ignored}"
        )
        print(f"  identifier: 0x{identifier:016X}")
        for field_idx in range(seq_hdr.last_field_in_sequence + 1):
          for element_idx in range(seq_hdr.last_element_in_field + 1):
            value = structpp.unpack("<Q", buffer[idx : idx + 8])[0]
            idx += 8
            print(f"  field {field_idx}, element {element_idx}: {hex(value)}")
        print("")
      print("")

  def pack(self, maintain_buffers: bool, pad_buffers: bool):
    """Packs the TD metadata."""
    output = b""
    if maintain_buffers:  # Old method, use the original buffer layout
      for buffer in self.buffers:
        output += structpp.pack(
            _TD_LIST_HEADER_FORMAT,
            buffer.list_header.list_buff_size,
            buffer.list_header.num_sequences,
            buffer.list_header.reserved,
        )
        for sequence in buffer.sequences:
          seq_bin = structpp.pack(_TD_SEQUENCE_HEADER_FORMAT, *sequence.header)
          output += seq_bin
          for field in sequence.fields:
            for element in field:
              element_bin = structpp.pack("<Q", element)
              output += element_bin
        # Pad out to 4KB if needed.
        if pad_buffers and len(output) % 4096 != 0:
          pad_len = (4096 - len(output) % 4096)
          print(f"Padding {pad_len} bytes to 4KB")
          output += b"\x42" * pad_len
    else:  # New method, regenerate buffers.
      def generate_buffer(num_sequences, seq_blobs: list[bytes]):
        output = structpp.pack(
            _TD_LIST_HEADER_FORMAT,
            8 + sum(len(seq_blob) for seq_blob in seq_blobs),
            num_sequences,
            0,
        )
        output += b"".join(seq_blobs)
        if len(output) > 4096:
          raise ValueError(f"Output is too large: {len(output)} bytes")
        # Pad out to 4KB if needed.
        if pad_buffers and len(output) % 4096 != 0:
          pad_len = (4096 - len(output) % 4096)
          print(f"Padding {pad_len} bytes to 4KB")
          output += b"\x42" * pad_len
        return output

      sequence_blobs = []
      for sequence in self.total_sequences:
        seq_bin = b""
        seq_bin += structpp.pack(_TD_SEQUENCE_HEADER_FORMAT, *sequence.header)
        for field in sequence.fields:
          for element in field:
            element_bin = structpp.pack("<Q", element)
            seq_bin += element_bin
        sequence_blobs.append(seq_bin)
      running_size = 0
      last_seq_idx = 0
      for seq_idx, seq_blob in enumerate(sequence_blobs):
        running_size += len(seq_blob)
        if running_size >= 4096:
          print(f"Cutting new buffer at [{last_seq_idx}, {seq_idx}]")
          output += generate_buffer(
              seq_idx - last_seq_idx, sequence_blobs[last_seq_idx:seq_idx]
          )
          last_seq_idx = seq_idx
          running_size = 0
      # If last sequence is very large, we might need to cut it separately.
      if (
          sum(len(seq_blob) for seq_blob in sequence_blobs[last_seq_idx:])
          >= 4096
      ):
        print(
            f"Cutting new buffer at [{last_seq_idx}:{len(sequence_blobs) - 1}]"
        )
        output += generate_buffer(
            (len(sequence_blobs) - 1) - last_seq_idx,
            sequence_blobs[last_seq_idx : len(sequence_blobs) - 1],
        )
        last_seq_idx = len(sequence_blobs) - 1
        # raise ValueError(f"Last sequence is too large: {len(sequence_blobs[-1])} bytes")
      print(f"Cutting new buffer at [{last_seq_idx}:]")
      output += generate_buffer(
          len(sequence_blobs) - last_seq_idx, sequence_blobs[last_seq_idx:]
      )

    return output

  def _set_attr(self, obj, attr_path, value):
    """Sets an attribute of an object using a path."""
    attrs = attr_path.split(".")
    # Traverse to the parent of what we are setting.
    # At each step, we get the next object in the path.
    obj_path = [obj]
    for attr in attrs[:-1]:
      match = re.match(r"(\w+)\[(\d+)\]", attr)
      if match:
        name, index = match.groups()
        obj_path.append(getattr(obj_path[-1], name)[int(index)])
      else:
        obj_path.append(getattr(obj_path[-1], attr))

    # Now, set the attribute. We may need to reconstruct tuples.
    val_to_set = value
    attr_to_set = attrs[-1]
    obj_to_change = obj_path[-1]

    if (
        isinstance(obj_to_change, TdSequence)
        and hasattr(obj_to_change, "header")
        and attr_to_set in obj_to_change.header._fields
    ):
      # This is a special case to edit header fields without '.header'
      new_header = obj_to_change.header._replace(**{attr_to_set: val_to_set})
      obj_to_change.header = new_header
      return

    # Handle list access like fields[0][0]
    list_access_match = re.match(r"^(\w+)((?:\[\d+\])+)$", attr_to_set)
    if list_access_match:
      name, indices_str = list_access_match.groups()
      indices = [int(i) for i in re.findall(r"\[(\d+)\]", indices_str)]

      list_to_modify = getattr(obj_to_change, name)

      # Traverse to the parent list
      parent_list = list_to_modify
      for index in indices[:-1]:
        parent_list = parent_list[index]

      # Set the value
      parent_list[indices[-1]] = val_to_set
      return  # we are done, lists are mutable.

    if isinstance(obj_to_change, tuple) and hasattr(obj_to_change, "_replace"):
      new_obj = obj_to_change._replace(**{attr_to_set: val_to_set})
      val_to_set = new_obj
    else:
      setattr(obj_to_change, attr_to_set, val_to_set)
      return

    # Backtrack to update parents of the new tuple.
    for i in range(len(obj_path) - 2, -1, -1):
      parent_obj = obj_path[i]
      attr_on_parent = attrs[i]

      match = re.match(r"(\w+)\[(\d+)\]", attr_on_parent)
      if match:
        name, index = match.groups()
        # list is mutable, so we can just set item
        getattr(parent_obj, name)[int(index)] = val_to_set
        return  # done
      else:
        if isinstance(parent_obj, tuple) and hasattr(parent_obj, "_replace"):
          new_parent = parent_obj._replace(**{attr_on_parent: val_to_set})
          val_to_set = new_parent
        else:
          setattr(parent_obj, attr_on_parent, val_to_set)
          return  # done

  def edit(self, edit_command: str):
    """Edits the TD metadata."""
    target_field, value_str = edit_command.split("=", 1)
    value = literal_eval(value_str)
    self._set_attr(self, target_field, value)


def main():
  parser = ArgumentParser(description="mig_bundle_edit")
  parser.add_argument(
      "--bundle",
      type=str,
      default="bundle.bin",
      help="file for the metadata bundle",
  )
  parser.add_argument(
      "--action",
      type=str,
      choices=[
          "insert_sequence",
          "remove",
          "modify",
          "dump",
          "create_template",
      ],
      help="action to perform",
      required=True,
  )
  parser.add_argument(
      "--index",
      type=int,
      help="index of the sequence to modify",
      default=-1,
  )
  parser.add_argument(
      "--edit",
      action="append",
      type=str,
      help=(
          "edit commands (--edit=buffers[0].list_buff_size=20"
          " --edit=buffers[0].sequences[0].header.field_code=0x1234)"
      ),
  )
  parser.add_argument(
      "--identifier",
      type=str,
      help="identifier to use",
      default="-1",
  )
  parser.add_argument(
      "--elements",
      type=str,
      help="elements to use [1,2,3,4]",
      default="0",
  )
  parser.add_argument(
      "--output",
      type=str,
      help="output file to use",
  )
  parser.add_argument(
      "--maintain_buffers",
      action="store_true",
      help="maintain buffers when packing",
      default=False,
  )
  parser.add_argument(
      "--pad_buffers",
      type=bool,
      help="pad buffers to 4KB",
      default=True,
  )
  args = parser.parse_args()

  if args.action == "create_template":
    if not args.output:
      raise ValueError("No output file provided")
    # Special case, don't open input file. Instead create output file.
    metadata = TdMetadata()
    metadata.add_buffer(list_buff_size=8, num_sequences=0)
    metadata.append_sequence(
        buffer_idx=0,
        field_code=0x1234,
        element_size_code=1,
        last_element_in_field=4,
        last_field_in_sequence=2,
        inc_size=1,
        write_mask_valid=0xFF,
        context_code=1,
        class_code=2,
    )
    # metadata.add_field()
    # metadata.add_element()
    with open(args.output, "wb") as f:
      f.write(metadata.pack(args.maintain_buffers, args.pad_buffers))
    return

  identifier = int(args.identifier, 16)

  metadata = TdMetadata(args.bundle)

  if args.action == "dump":
    metadata.dump(identifier)
  elif args.action == "insert_sequence":
    elements = [int(x, 0) for x in args.elements.split(",")]
    metadata.insert_sequence(args.index, identifier, elements)
  elif args.action == "remove":
    raise ValueError("Not implemented")
  elif args.action == "modify":
    if args.edit:
      for edit_command in args.edit:
        metadata.edit(edit_command)
    else:
      raise ValueError("No edit commands provided")
  else:
    raise ValueError(f"Unknown action: {args.action}")

  if args.output:
    with open(args.output, "wb") as f:
      f.write(metadata.pack(args.maintain_buffers, args.pad_buffers))
  else:
    #metadata.dump(-1)
    pass


if __name__ == "__main__":
  main()
