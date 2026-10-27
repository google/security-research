/**
 * @name Kernel struct locations and re-rolled field layouts
 * @description Extracts all compiled runtime kernel struct/union definitions
 *   (both vmlinux and loadable .ko modules) along with their flattened leaf
 *   fields, cumulative byte offsets across anonymous unions/structs, bitfield
 *   spans, function-pointer indicators, and flexible-array flags.
 * @id cpp/dashboard/structs
 * @kind table
 * @tags security kernel structs
 */

import cpp
import struct_utils

int fieldBitOffset(Field f) {
  if f instanceof BitField then result = f.(BitField).getBitOffset() else result = -1
}

int fieldBitSize(Field f) {
  if f instanceof BitField then result = f.(BitField).getNumBits() else result = -1
}

int fieldArrayLen(Field f) {
  if
    f.getUnspecifiedType() instanceof ArrayType and
    f.getUnspecifiedType().(ArrayType).hasArraySize()
  then result = f.getUnspecifiedType().(ArrayType).getArraySize()
  else result = -1
}

int fieldIsFuncPtr(Field f) { if isFuncPtrField(f) then result = 1 else result = 0 }

int fieldIsFlex(Field f) { if isFlexibleArrayField(f) then result = 1 else result = 0 }

int structHasFlex(Class root) {
  resolvedRootStruct(root, _, _) and
  if exists(Field rf | leafFieldOfRoot(rf, root, _, _) and isFlexibleArrayField(rf))
  then result = 1
  else result = 0
}

int structMemberCount(Class root) {
  resolvedRootStruct(root, _, _) and
  result = count(Field rf | leafFieldOfRoot(rf, root, _, _))
}

from
  Class root,
  string structName,
  int isTypedef,
  Field f,
  int byteOffset,
  string fieldPath
where
  resolvedRootStruct(root, structName, isTypedef) and
  leafFieldOfRoot(f, root, byteOffset, fieldPath)
select
  structName as struct_name,
  root.getLocation().getFile().getRelativePath() as file_path,
  root.getLocation().getStartLine() as start_line,
  structEndLine(root) as end_line,
  root.getSize() as byte_size,
  structMemberCount(root) as member_count,
  0 as is_anonymous,
  isTypedef as is_typedef,
  structHasFlex(root) as has_flex_member,
  f.getName() as field_name,
  fieldPath as field_path,
  f.getType().getName() as field_type,
  byteOffset as byte_offset,
  fieldBitOffset(f) as bit_offset,
  fieldBitSize(f) as bit_size,
  fieldIsFuncPtr(f) as is_funcptr,
  fieldIsFlex(f) as is_flex,
  fieldArrayLen(f) as array_len
