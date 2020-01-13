from typing import NewType

Int = NewType('Int', int)  # int32
UInt = NewType('UInt', int)  # uint32
UInt8 = NewType('UInt8', int)  # uint8
UInt16 = NewType('UInt16', int)  # uint16
UInt32 = NewType('UInt32', int)  # uint32
UInt64 = NewType('UInt64', int)  # uint64
ULong = NewType('ULong', int)  # uint64

Size_t = NewType('size_t', UInt32) # uint32
Char = NewType('Char', UInt8)

WORD = NewType('WORD', UInt16)  # uint16
DWORD = NewType('DWORD', int)  # uint32
QWORD = NewType('QWORD', int)  # uint64
