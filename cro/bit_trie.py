"""
implementation of modified bit_trie for CRO files
CRO uses this for fast symbol name lookups
https://gist.github.com/wwylele/325d53ee6a0f1dff6aa3473377335d93
https://gist.github.com/wwylele/325d53ee6a0f1dff6aa3473377335d93#exported-name-tree
"""

import dataclasses
from .stream_wrapper import as_stream_wrapper, StreamWrappable


@dataclasses.dataclass
class Branch:
	index: int
	end: bool

	@classmethod
	def from_raw(cls, value: int):
		return cls(
			index=value & ((2 << 14) - 1),
			end=bool(value >> 15)
		)

	def to_raw(self):
		return (
			(self.end << 15) +
			self.index
		)


@dataclasses.dataclass
class Node:
	bit_address: int
	left: Branch
	right: Branch
	value: int


@dataclasses.dataclass
class BitTrie:
	nodes: list[Node]

	@classmethod
	def from_stream(cls, stream: StreamWrappable, node_count: int):
		"""Initialize a BitTrie from a stream"""
		stream = as_stream_wrapper(stream)
		nodes = []
		for index in range(node_count):
			bit_address = stream.read_uint16()
			left = Branch.from_raw(stream.read_uint16())
			right = Branch.from_raw(stream.read_uint16())
			value = stream.read_uint16()
			nodes.append(Node(
				bit_address=bit_address,
				left=left,
				right=right,
				value=value
			))

		return cls(nodes=nodes)

	def to_stream(self, stream: StreamWrappable):
		"""Write a BitTrie to a stream"""
		stream = as_stream_wrapper(stream)
		for node in self.nodes:
			stream.write_uint16(node.bit_address)
			stream.write_uint16(node.left.to_raw())
			stream.write_uint16(node.right.to_raw())
			stream.write_uint16(node.value)

	@classmethod
	def from_values(cls, values: list[bytes]):
		"""Initialize a BitTrie from a list of bytestrings"""
		self = cls(nodes=[
			Node(
				bit_address=-1,
				left=Branch(0, True),
				right=Branch(0, True),
				value=index
			) for index, value in enumerate(values)
		])

		max_byte_length = max(len(v) for v in values)
		max_bit_length = max_byte_length * 8

		# go from relative to absolute offsets
		self._build(begin_index=0, end_index=len(self.nodes), bit_length=max_bit_length, values=values)
		for index, node in enumerate(self.nodes):
			node.left.index += index
			node.right.index += index
			if node.bit_address == -1:
				node.bit_address = 0xFFFF

		return self

	def at_node(self, key: bytes) -> Node:
		"""Return the node with the specified key"""
		next_branch: Branch = self.nodes[0].left
		while True:
			current_index = next_branch.index
			if next_branch.end:
				return self.nodes[current_index]
			if string_tester(key, self.nodes[current_index].bit_address):
				next_branch = self.nodes[current_index].right
			else:
				next_branch = self.nodes[current_index].left

	def at(self, key: bytes):
		"""Return the value of the node with the specified key"""
		return self.at_node(key).value

	def _build(
			self,
			begin_index: int,
			end_index: int,
			bit_length: int,
			values: list[bytes]
	):
		nodes = self.nodes

		if end_index - begin_index <= 1:
			return

		pass_counts = {}

		for node in nodes[begin_index:end_index]:
			for bit in range(bit_length):
				if string_tester(values[node.value], bit):
					pass_counts[bit] = pass_counts.get(bit, 0) + 1

		# find the best address that partition the elements evenly
		best_address = None
		badness = 0xFFFFFFFF
		for bit in range(bit_length):
			current = abs(pass_counts.get(bit, 0) - (end_index - begin_index) / 2)
			if current < badness:
				badness = current
				best_address = bit

		first = []
		last = []
		for node in nodes[begin_index:end_index]:
			key = values[node.value]
			if string_tester(key, best_address):
				last.append(node)
			else:
				first.append(node)

		# partition "in place"
		nodes[begin_index:end_index] = [*first, *last]

		self._build(
			begin_index=begin_index,
			end_index=begin_index + len(first),
			bit_length=bit_length,
			values=values
		)
		self._build(
			begin_index=begin_index + len(first),
			end_index=end_index,
			bit_length=bit_length,
			values=values
		)

		begin = nodes[begin_index]
		partition_distance = len(first)
		if partition_distance == (end_index - begin_index) or partition_distance == 0:
			raise ValueError("duplicated keys")

		partition_node = nodes[begin_index + partition_distance]
		partition_node.right = Branch(
			index=partition_node.left.index,
			end=partition_node.left.end
		)
		partition_node.left = Branch(
			index=begin.left.index,
			end=begin.left.end
		)
		partition_node.left.index -= partition_distance
		partition_node.bit_address = best_address

		begin.left.index = partition_distance
		begin.left.end = False


def string_tester(key: bytes, position: int):
	byte = position >> 3
	if byte >= len(key):
		return False
	return bool((key[byte] >> (position & 7)) & 1)
