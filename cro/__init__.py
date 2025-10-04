"""
implementation of CRO files

based on:
https://gist.github.com/wwylele/325d53ee6a0f1dff6aa3473377335d93
https://github.com/kynex7510/3ds_ida/blob/cro/loaders/ctr_cro_loader.py
"""

from __future__ import annotations

import dataclasses
import hashlib
import io
import struct
import sys
from enum import IntEnum

from .bit_trie import BitTrie
from .stream_wrapper import as_stream_wrapper, StreamWrappable, StreamWrapper

MAGIC = b"CRO0"


def align_to(value: int, alignment: int):
	alignment -= 1
	return (value + alignment) & ~alignment


class SegmentType(IntEnum):
	TEXT = 0
	RODATA = 1
	DATA = 2
	BSS = 3


@dataclasses.dataclass
class SegmentMeta:
	offset: int
	data_size: int
	type: SegmentType

	@classmethod
	def from_stream(cls, stream: StreamWrapper):
		return cls(
			offset=stream.read_uint32(),
			data_size=stream.read_uint32(),
			type=SegmentType(stream.read_uint32())
		)

	def to_stream(self, stream: StreamWrapper):
		stream.write_uint32(self.offset)
		stream.write_uint32(self.data_size)
		stream.write_uint32(self.type)


@dataclasses.dataclass
class Segment:
	type: SegmentType
	data: bytes

	def __repr__(self):
		return f"<Segment type={self.type.name} len(data)={len(self.data)}>"


class RelocationType(IntEnum):
	ARM_NONE = 0
	ARM_ABS32 = 2
	ARM_REL32 = 3
	ARM_THM_PC22 = 10
	ARM_CALL = 28
	ARM_JUMP24 = 29
	ARM_TARGET1 = 38
	ARM_PREL31 = 42


@dataclasses.dataclass
class Relocation:
	segment_type: SegmentType
	segment_offset: int  # offset from the start of the segment at segment_type
	type: RelocationType
	base_index: int
	addend: int

	@classmethod
	def from_stream(cls, stream: StreamWrapper):
		raw_offset = stream.read_uint32()
		reloc_type = RelocationType(stream.read_uint8())
		base_index = stream.read_uint8()
		stream.skip(2)
		addend = stream.read_uint32()
		return cls(
			segment_type=SegmentType(raw_offset & 0xF),
			segment_offset=raw_offset >> 4,
			type=reloc_type,
			base_index=base_index,
			addend=addend
		)

	def to_stream(self, stream: StreamWrapper):
		raw_offset = self.segment_offset << 4 + self.segment_type
		stream.write_uint32(raw_offset)
		stream.write_uint8(self.type)
		stream.write_uint8(self.base_index)
		stream.skip(2)
		stream.write_uint32(self.addend)


@dataclasses.dataclass
class ExportedNamedSymbol:
	segment_type: SegmentType
	segment_offset: int
	name: str


@dataclasses.dataclass
class ImportedNamedSymbol:
	id: int
	name: str


@dataclasses.dataclass
class ExportedIndexedSymbol:
	segment_type: SegmentType
	segment_offset: int


_HASHES_STRUCT_FMT = "32s32s32s32s"  # hashes

_HEADER_STRUCT_FMT = (
	"4s"  # magic
	"45I"  # 45 uint32s
)


@dataclasses.dataclass
class CROFileHashes:
	sha256_0: bytes
	sha256_1: bytes
	sha256_2: bytes
	sha256_3: bytes

	@classmethod
	def from_stream(cls, stream: StreamWrapper):
		return cls(*struct.unpack(
			_HASHES_STRUCT_FMT,
			stream.read(struct.calcsize(_HASHES_STRUCT_FMT))
		))

	def to_stream(self, stream: StreamWrapper):
		stream.write(struct.pack(
			_HASHES_STRUCT_FMT,
			*dataclasses.asdict(self).values()
		))


@dataclasses.dataclass
class CROFileHeader:
	magic: bytes
	name_offset: int

	next_module: int
	prev_module: int
	file_size: int

	bss_size: int
	fixed_size: int
	zero: int
	nrro_tag: int
	onload_tag: int
	onexit_tag: int
	onunresolved_tag: int

	code_offset: int
	code_size: int
	data_offset: int
	data_size: int

	module_name_offset: int
	module_name_size: int

	segment_table_offset: int
	segment_table_count: int

	exported_named_symbol_table_offset: int
	exported_named_symbol_table_count: int

	exported_indexed_symbol_table_offset: int
	exported_indexed_symbol_table_count: int

	exported_strings_offset: int
	exported_strings_size: int

	exported_name_tree_offset: int
	exported_name_tree_node_count: int

	imported_module_table_offset: int
	imported_module_table_count: int

	external_relocation_table_offset: int
	external_relocation_table_count: int

	imported_named_symbol_table_offset: int
	imported_named_symbol_table_count: int

	imported_indexed_symbol_table_offset: int
	imported_indexed_symbol_table_count: int

	imported_anonymous_symbol_table_offset: int
	imported_anonymous_symbol_table_count: int

	imported_strings_offset: int
	imported_strings_size: int

	static_anonymous_symbol_table_offset: int
	static_anonymous_symbol_table_count: int

	relocation_table_offset: int
	relocation_table_count: int

	static_anonymous_patch_table_offset: int
	static_anonymous_patch_table_count: int

	@classmethod
	def from_stream(cls, stream: StreamWrapper):
		return cls(*struct.unpack(
			_HEADER_STRUCT_FMT,
			stream.read(struct.calcsize(_HEADER_STRUCT_FMT))
		))

	def to_stream(self, stream: StreamWrapper):
		stream.write(struct.pack(
			_HEADER_STRUCT_FMT,
			*dataclasses.asdict(self).values()
		))


@dataclasses.dataclass
class CROFile:
	name: str
	module_name: str
	segment_table: dict[SegmentType, Segment]
	relocations: list[Relocation]
	external_relocations: list[Relocation]
	exported_named_symbols: list[ExportedNamedSymbol]
	exported_indexed_symbols: list[ExportedIndexedSymbol]
	imported_named_symbols: list[ImportedNamedSymbol]

	def __repr__(self):
		return f"<CROFile name={self.name!r} len(exported_named_symbols)={len(self.exported_named_symbols)}>"

	@property
	def segments(self):
		return list(self.segment_table.values())

	@classmethod
	def from_stream(cls, stream: StreamWrappable):
		stream = as_stream_wrapper(stream)

		hashes = CROFileHashes.from_stream(stream)
		header = CROFileHeader.from_stream(stream)
		if header.magic != MAGIC:
			raise ValueError("not a CRO")

		if header.imported_module_table_count > 0:
			print(f"Warning: parser does not support {header.imported_module_table_count=}", file=sys.stderr)
		if header.imported_indexed_symbol_table_count > 0:
			print(f"Warning: parser does not support {header.imported_indexed_symbol_table_count=}", file=sys.stderr)
		if header.imported_anonymous_symbol_table_count > 0:
			print(f"Warning: parser does not support {header.imported_anonymous_symbol_table_count=}", file=sys.stderr)
		if header.static_anonymous_symbol_table_count > 0:
			print("Warning: parser does not support static_anonymous_symbol_table_count", file=sys.stderr)
		if header.static_anonymous_patch_table_count > 0:
			print("Warning: parser does not support static_anonymous_patch_table", file=sys.stderr)

		# Verify hashes
		stream.seek(0x80)
		sha256_0_data = stream.read_up_to(header.code_offset)
		sha256_1_data = stream.read_up_to(header.module_name_offset)
		sha256_2_data = stream.read_up_to(header.data_offset)
		sha256_3_data = stream.read_up_to(header.data_offset + header.data_size)

		sha256_0_result = hashlib.sha256(sha256_0_data).digest()
		sha256_1_result = hashlib.sha256(sha256_1_data).digest()
		sha256_2_result = hashlib.sha256(sha256_2_data).digest()
		sha256_3_result = hashlib.sha256(sha256_3_data).digest()

		hashes_match = True
		table_io = io.StringIO()
		print(f"| # | Good | {'File hash':^64} | {'Calculated hash':^64} |", file=table_io)
		print(f"| - | {'-' * 4} | {'-' * 64} | {'-' * 64} |", file=table_io)
		for index, (hash_0, hash_1) in enumerate([
			(hashes.sha256_0, sha256_0_result),
			(hashes.sha256_1, sha256_1_result),
			(hashes.sha256_2, sha256_2_result),
			(hashes.sha256_3, sha256_3_result),
		]):
			matches = hash_0 == hash_1
			print(f"| {index} | {('Yes' if matches else 'No'):>4} | {hash_0.hex()} | {hash_1.hex()} |", file=table_io)
			if not matches:
				hashes_match = False

		if not hashes_match:
			print("Warning, hashes do not match! CRO file may be broken.", file=sys.stderr)
			print(table_io.getvalue(), file=sys.stderr)

		# Load name
		stream.seek(header.name_offset)
		name = stream.read_c_string().decode("ascii")

		# Load module name
		stream.seek(header.module_name_offset)
		module_name = stream.read(header.module_name_size)[:-1].decode("ascii")

		# Load segment table
		stream.seek(header.segment_table_offset)
		segment_meta_table: dict[SegmentType, SegmentMeta] = {}
		for _ in range(header.segment_table_count):
			segment_meta = SegmentMeta.from_stream(stream)
			if segment_meta.data_size == 0:
				continue
			if segment_meta.type in segment_meta_table:
				raise ValueError(f"more than one segment of type {segment_meta.type}")
			# override: BSS does not use segment_offset
			if segment_meta.type == SegmentType.BSS:
				data_segment = segment_meta_table[SegmentType.DATA]
				segment_meta.offset = data_segment.offset + data_segment.data_size
				segment_meta.data_size = header.bss_size
			elif segment_meta.type == SegmentType.DATA:
				if header.data_offset != segment_meta.offset:
					raise ValueError("data_offset does not match")
				elif header.data_size != segment_meta.data_size:
					raise ValueError("data_size does not match")
			elif segment_meta.type == SegmentType.TEXT:
				if header.code_offset != segment_meta.offset:
					raise ValueError("code_offset does not match")

			segment_meta_table[segment_meta.type] = segment_meta

		segment_table: dict[SegmentType, Segment] = {}
		for segment_meta in segment_meta_table.values():
			stream.seek(segment_meta.offset)
			if segment_meta.offset + segment_meta.data_size > header.file_size:
				print(f"Warning: EOF early for segment {segment_meta.type.name}!", file=sys.stderr)

			segment = Segment(
				data=stream.read_until_eof(segment_meta.data_size),
				type=segment_meta.type
			)
			segment_table[segment_meta.type] = segment

		# Load relocation table
		stream.seek(header.relocation_table_offset)
		relocations = [Relocation.from_stream(stream) for _ in range(header.relocation_table_count)]

		stream.seek(header.external_relocation_table_offset)
		external_relocations = [Relocation.from_stream(stream) for _ in range(header.external_relocation_table_count)]

		# Load named export table
		exported_named_symbols = []
		for i in range(header.exported_named_symbol_table_count):
			stream.seek(header.exported_named_symbol_table_offset + (i * 0x8))

			name_offset = stream.read_uint32()
			segment_raw_offset = stream.read_uint32()

			# name_offset is relative to start but its also within exported_strings
			if header.exported_strings_offset > name_offset > (
					header.exported_strings_offset + header.exported_strings_size):
				raise ValueError("string out of place")
			stream.seek(name_offset)
			symbol_name = stream.read_c_string().decode("ascii")

			exported_named_symbols.append(ExportedNamedSymbol(
				segment_type=SegmentType(segment_raw_offset & 0xF),
				segment_offset=segment_raw_offset >> 4,
				name=symbol_name
			))

		# Load exported name tree
		stream.seek(header.exported_name_tree_offset)

		_trie = BitTrie.from_stream(stream, node_count=header.exported_name_tree_node_count)

		# Load indexed export table
		exported_indexed_symbols = []
		stream.seek(header.exported_indexed_symbol_table_offset)
		for i in range(header.exported_indexed_symbol_table_count):
			segment_raw_offset = stream.read_uint32()

			exported_indexed_symbols.append(ExportedIndexedSymbol(
				segment_type=SegmentType(segment_raw_offset & 0xF),
				segment_offset=segment_raw_offset >> 4
			))

		imported_named_symbols: list[ImportedNamedSymbol] = []
		for i in range(header.imported_named_symbol_table_count):
			stream.seek(header.imported_named_symbol_table_offset + (i * 0x8))
			name_offset = stream.read_uint32()
			symbol_id = stream.read_uint32()

			# name_offset is relative to start but its also within exported_strings
			if header.imported_strings_offset > name_offset > (
					header.imported_strings_offset + header.imported_strings_size):
				raise ValueError("string out of place")
			stream.seek(name_offset)
			symbol_name = stream.read_c_string().decode("ascii")

			imported_named_symbols.append(ImportedNamedSymbol(
				id=symbol_id,
				name=symbol_name
			))

		return cls(
			name=name,
			module_name=module_name,
			segment_table=segment_table,
			relocations=relocations,
			external_relocations=external_relocations,
			exported_named_symbols=exported_named_symbols,
			exported_indexed_symbols=exported_indexed_symbols,
			imported_named_symbols=imported_named_symbols
		)

	def to_stream(self, stream: StreamWrappable):
		stream = as_stream_wrapper(stream)

		stream.seek(0x0)
		header_offset = stream.tell()

		segments = self.segments
		code_segments = [
			segment for segment in segments if segment.type in {
				SegmentType.TEXT, SegmentType.RODATA
			}
		]
		data_segments = [
			segment for segment in segments if segment.type in {
				SegmentType.DATA, SegmentType.BSS
			}
		]

		segment_meta_table: dict[SegmentType, SegmentMeta] = {}

		stream.seek(0x180)
		code_offset = stream.tell()
		for segment in code_segments:
			segment_meta_table[segment.type] = SegmentMeta(
				type=segment.type,
				offset=stream.tell(),
				data_size=len(segment.data)
			)
			stream.write(segment.data)
			stream.pad_to(0x1000)
		code_size = stream.tell() - code_offset

		# Write name
		name_offset = stream.tell()
		stream.write_c_string(self.name.encode("ascii"))

		if self.name != self.module_name:
			module_name_offset = stream.tell()
			stream.write_c_string(self.module_name.encode("ascii"))
		else:
			module_name_offset = name_offset

		module_name_size = stream.tell() - module_name_offset

		# Prepare to write segment table
		segment_table_offset = stream.tell()

		stream.skip((4 * 3) * (len(self.segment_table) + 1))

		# Prepare to write exported named symbol table
		exported_named_symbol_table_offset = stream.tell()
		stream.skip(0x8 * len(self.exported_named_symbols))

		# Write exported name tree
		exported_name_tree_offset = stream.tell()
		trie = BitTrie.from_values([symbol.name.encode("ascii") for symbol in self.exported_named_symbols])
		trie.to_stream(stream)

		# Write exported indexed symbol table
		exported_indexed_symbol_table_offset = stream.tell()
		for symbol in self.exported_indexed_symbols:
			raw_offset = (symbol.segment_offset << 4) + symbol.segment_type
			stream.write_uint32(raw_offset)

		# Write strings
		stream.pad_to(4)
		exported_strings_offset = stream.tell()
		exported_strings_offsets = []
		# Create all the strings (will be written later)
		for symbol in self.exported_named_symbols:
			exported_strings_offsets.append(stream.tell())
			stream.write_c_string(symbol.name.encode("ascii"))
		exported_strings_size = stream.tell() - exported_strings_offset

		# Prepare to write external relocation table
		stream.pad_to(4)
		external_relocation_table_offset = stream.tell()
		imported_module_table_offset = stream.tell()  # NOT IMPLEMENTED

		# Go back and write exported named symbol table
		stream.seek(exported_named_symbol_table_offset)
		for (index, symbol) in enumerate(self.exported_named_symbols):
			raw_offset = (symbol.segment_offset << 4) + symbol.segment_type
			stream.write_uint32(exported_strings_offsets[index])
			stream.write_uint32(raw_offset)

		# write external relocations
		stream.seek(external_relocation_table_offset)
		for relocation in self.external_relocations:
			relocation.to_stream(stream)

		# imports time!
		# prepare to write imported named symbol table
		imported_named_symbol_table_offset = stream.tell()
		stream.skip(0x8 * len(self.imported_named_symbols))

		imported_indexed_symbol_table_offset = stream.tell()  # NOT IMPLEMENTED
		imported_anonymous_symbol_table_offset = stream.tell()  # NOT IMPLEMENTED
		imported_strings_offset = stream.tell()
		imported_strings_offsets = []
		# Create all the strings (will be written later)
		for symbol in self.imported_named_symbols:
			imported_strings_offsets.append(stream.tell())
			stream.write_c_string(symbol.name.encode("ascii"))
		imported_strings_size = stream.tell() - imported_strings_offset

		static_anonymous_symbol_table_offset = stream.tell()
		static_anonymous_patch_table_offset = stream.tell()

		# Prepare to write relocation table
		relocation_table_offset = stream.tell()

		# Go back and write imported named symbol table
		stream.seek(imported_named_symbol_table_offset)
		for (index, symbol) in enumerate(self.imported_named_symbols):
			stream.write_uint32(imported_strings_offsets[index])
			stream.write_uint32(symbol.id)

		# Write relocation table
		stream.seek(relocation_table_offset)
		for relocation in self.relocations:
			relocation.to_stream(stream)

		# Write data segments
		for segment in data_segments:
			stream.pad_to(0x10)
			segment_meta_table[segment.type] = SegmentMeta(
				type=segment.type,
				offset=stream.tell(),
				data_size=len(segment.data)
			)
			stream.write(segment.data)

		end_offset = stream.tell()

		# Go back and write meta table
		stream.seek(segment_table_offset)
		for segment_meta in segment_meta_table.values():
			if segment_meta.type == SegmentType.BSS:
				segment_meta = dataclasses.replace(
					segment_meta,
					offset=0
					# data_size is different too but ill leave it alone
				)
			segment_meta.to_stream(stream)

		# finally, calc hashes and write header
		data_offset = segment_meta_table[SegmentType.DATA].offset
		data_size = segment_meta_table[SegmentType.DATA].data_size

		stream.seek(header_offset)
		stream.skip(0x20*4)
		header = CROFileHeader(
			magic=MAGIC,
			name_offset=name_offset,

			next_module=0,
			prev_module=0,
			file_size=end_offset-header_offset,

			bss_size=segment_meta_table[SegmentType.BSS].data_size,
			fixed_size=0,
			zero=0,
			nrro_tag=0,
			onload_tag=0xFFFFFFFF,
			onexit_tag=0xFFFFFFFF,
			onunresolved_tag=0xFFFFFFFF,

			code_offset=code_offset,
			code_size=code_size,
			data_offset=data_offset,
			data_size=data_size,

			module_name_offset=module_name_offset,
			module_name_size=module_name_size,

			segment_table_offset=segment_table_offset,
			segment_table_count=len(self.segment_table)+1,

			exported_named_symbol_table_offset=exported_named_symbol_table_offset,
			exported_named_symbol_table_count=len(self.exported_named_symbols),

			exported_indexed_symbol_table_offset=exported_indexed_symbol_table_offset,
			exported_indexed_symbol_table_count=len(self.exported_indexed_symbols),

			exported_strings_offset=exported_strings_offset,
			exported_strings_size=exported_strings_size,

			exported_name_tree_offset=exported_name_tree_offset,
			exported_name_tree_node_count=len(trie.nodes),

			imported_module_table_offset=imported_module_table_offset,
			imported_module_table_count=0,

			external_relocation_table_offset=external_relocation_table_offset,
			external_relocation_table_count=len(self.external_relocations),

			imported_named_symbol_table_offset=imported_named_symbol_table_offset,
			imported_named_symbol_table_count=len(self.imported_named_symbols),

			imported_indexed_symbol_table_offset=imported_indexed_symbol_table_offset,
			imported_indexed_symbol_table_count=0,

			imported_anonymous_symbol_table_offset=imported_anonymous_symbol_table_offset,
			imported_anonymous_symbol_table_count=0,

			imported_strings_offset=imported_strings_offset,
			imported_strings_size=imported_strings_size,

			static_anonymous_symbol_table_offset=static_anonymous_symbol_table_offset,
			static_anonymous_symbol_table_count=0,

			relocation_table_offset=relocation_table_offset,
			relocation_table_count=len(self.relocations),

			static_anonymous_patch_table_offset=static_anonymous_patch_table_offset,
			static_anonymous_patch_table_count=0
		)
		header.to_stream(stream)

		# write hashes
		stream.seek(0x80)
		sha256_0_data = stream.read_up_to(code_offset)
		sha256_1_data = stream.read_up_to(module_name_offset)
		sha256_2_data = stream.read_up_to(data_offset)
		sha256_3_data = stream.read_up_to(data_offset + data_size)

		stream.seek(header_offset)
		hashes = CROFileHashes(
			sha256_0=hashlib.sha256(sha256_0_data).digest(),
			sha256_1=hashlib.sha256(sha256_1_data).digest(),
			sha256_2=hashlib.sha256(sha256_2_data).digest(),
			sha256_3=hashlib.sha256(sha256_3_data).digest()
		)
		hashes.to_stream(stream)

		# back to end :3
		stream.seek(end_offset)
		# yay done ^-^
