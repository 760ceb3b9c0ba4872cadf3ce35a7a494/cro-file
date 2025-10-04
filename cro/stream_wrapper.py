"""
simple typing.BinaryIO wrapper
"""


import io
import typing


class StreamWrapper:
	def __init__(self, stream: typing.BinaryIO):
		self._stream = stream
		self._endianness: typing.Literal["little", "big"] = "little"

	def read(self, length: int) -> bytes:
		data = self._stream.read(length)
		if len(data) < length:
			raise ValueError("no more data..")
		return data

	def write(self, data: bytes):
		if self._stream.write(data) != len(data):
			raise ValueError("couldn't write!!!!!!!!!!!")

	def pad_to(self, divisor: int):
		remainder = self.tell() % divisor
		if remainder > 0:
			self.skip(divisor - remainder)

	def seek(self, offset: int, whence: int = io.SEEK_SET):
		self._stream.seek(offset, whence)

	def tell(self) -> int:
		return self._stream.tell()

	def skip(self, count: int):
		self.seek(count, io.SEEK_CUR)

	def read_until_eof(self, length: typing.Optional[int] = None) -> bytes:
		return self._stream.read(length)

	def read_up_to(self, offset: int) -> bytes:
		current_offset = self.tell()
		if current_offset > offset:
			raise ValueError("cannot read backwards")
		return self.read(offset - current_offset)

	def read_byte(self):
		return self.read(1)

	def read_int(self, length: int, signed: bool = False):
		return int.from_bytes(self.read(length), self._endianness, signed=signed)

	def write_int(self, value: int, length: int, signed: bool = False):
		self.write(value.to_bytes(
			length=length,
			signed=signed,
			byteorder=self._endianness
		))

	def read_uint8(self):
		return self.read_int(1)

	def read_uint16(self):
		return self.read_int(2)

	def read_uint32(self):
		return self.read_int(4)

	def write_uint8(self, value: int):
		self.write_int(value, 1)

	def write_uint16(self, value: int):
		self.write_int(value, 2)

	def write_uint32(self, value: int):
		self.write_int(value, 4)

	def write_c_string(self, data: bytes):
		self.write(data)
		self.write(b"\x00")

	def read_c_string(self) -> bytes:
		out = io.BytesIO()
		while True:
			char = self.read_byte()
			if char == b"\x00":
				break
			out.write(char)
		return out.getvalue()


type StreamWrappable = typing.Union[typing.BinaryIO, StreamWrapper]


def as_stream_wrapper(value: StreamWrappable) -> StreamWrapper:
	if isinstance(value, StreamWrapper):
		return value
	return StreamWrapper(value)
