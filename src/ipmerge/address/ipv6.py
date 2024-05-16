from typing import Iterable, SupportsBytes, SupportsIndex, SupportsInt, overload
from enum import Enum

from .address import Address
from .ipv4 import IPv4_Address



class DualOutputMode(Enum):
	FORCE_NORMAL = 0
	VALUE_DEPENDENT = 1
	FORCE_DUAL = 2



class IPv6Segments(list[int], SupportsInt, SupportsBytes):
	@overload
	def __init__(self) -> None: ...
	@overload
	def __init__(self, initial: bytes) -> None: ...
	@overload
	def __init__(self, initial: Iterable[int]) -> None: ...
	@overload
	def __init__(self, initial: int) -> None: ...

	def __init__(self, initial: Iterable[int] | bytes | int | None = None) -> None:
		if initial == None:
			return super().__init__()
		
		if type(initial) == int:
			initial = initial.to_bytes(length=16, byteorder="big", signed=False)
		
		if type(initial) == bytes:
			if len(initial) > 16:
				raise ValueError()
			
			initial = initial.rjust(16, b"\0")
			initialList = list[int]()
			
			for i in range(0, len(initial), 2):
				initialList.append(initial[i] << 8 | initial[i + 1])
			
			return super().__init__(initialList)

		# At this point, only option remaining for initial is Iterable[int]
		initialIterable: Iterable[int] = initial # type: ignore

		for x in initialIterable:
			if x < 0 or x > 0xffff:
				raise self.__createValueError(x)
		return super().__init__(initialIterable)

	def __int__(self) -> int:
		result = 0
		for x in self:
			result = (result << 16) | x
		return result
	
	def __bytes__(self) -> bytes:
		byteList = list[int]()
		for x in self:
			byteList.append(x >> 8 & 0xff)
			byteList.append(x & 0xff)
		return bytes(byteList)
	
	@staticmethod
	def fromInt(value: int) -> "IPv6Segments":
		return IPv6Segments(value.to_bytes(length=16, byteorder="big", signed=False))
	
	@staticmethod
	def __createValueError(value: int):
		return ValueError(f"Value {value} ({hex(value)}) is outside of allowed range for IPv6 segment values (0 - 0xffff)")
	
	def append(self, item: int):
		if item < 0 or item > 0xffff:
			raise self.__createValueError(item)
		else:
			return super().append(item)
	
	def insert(self, index: SupportsIndex, item: int):
		if item < 0 or item > 0xffff:
			raise self.__createValueError(item)
		else:
			return super().insert(index, item)
	
	def extend(self, iterable: Iterable[int]):
		for x in iterable:
			if x < 0 or x > 0xffff:
				raise self.__createValueError(x)
		return super().extend(iterable)
	



class IPv6_Address(Address):
	def __init__(self, address: int | IPv6Segments, dual: bool = False):
		if type(address) == int:
			super().__init__(address)
			self._segments = IPv6Segments(address)
		elif type(address) == IPv6Segments:
			super().__init__(int(address))
			self._segments = address

		self._dual = dual
	
	@property
	def dual(self) -> bool:
		return self._dual
	
	@property
	def ipv4_part(self):
		return self.addressInt & 0xffffffff
	
	@property
	def ipv4(self):
		return IPv4_Address(self.ipv4_part)
	
	@property
	def string(self):	# for debugging
		return self.toString()
	
	@staticmethod
	def parse(string: str) -> "IPv6_Address | None":
		string = string.strip().replace(" ", "")
		
		if string == "::":
			return IPv6_Address(0, False)
		
		segments = string.split(":")

		if len(segments) > 8:
			return None
		
		segmentList = IPv6Segments()
		fillAt: None | int = None	# byte at which the 0-filling should start
		dual = False

		if string.startswith("::"):
			fillAt = 0
			segments = segments[2:]
		elif string.endswith("::"):
			segments = segments[:-2]
			fillAt = len(segments)

		for i, segment in enumerate(segments):
			if dual:	# Another segment after the IPv4 part of a dual address is invalid
				return None
			
			segment = segment.strip()
			if len(segment) == 0:
				if fillAt == None:
					fillAt = i
					continue
				else:
					return None
			
			if "." in segment:
				if i != len(segments) - 1:	# not on last segment
					return None
				if len(segments) > 7:	# segment count check for a dual address
					return None
				dual = True
				ipv4 = IPv4_Address.parse(segment)
				if ipv4 != None:
					segmentList.append((ipv4.addressInt >> 16) & 0xffff)
					segmentList.append(ipv4.addressInt & 0xffff)
					continue
				else:
					return None
			
			try:
				segmentInt = int(segment, base=16)
			except ValueError:
				return None
			
			if segmentInt < 0 or segmentInt > 0xffff:
				return None
			
			segmentList.append(segmentInt)

		if type(fillAt) == int:
			for _ in range(8 - len(segmentList)):
				segmentList.insert(fillAt, 0)
		
		return IPv6_Address(segmentList, dual)

	@staticmethod
	def findLongestZeroSegmentString(segments: list[int]) -> tuple[int | None, int]:
		maxZeros: int = 0
		maxZerosIndex: int | None = None
		currentZeros: int = 0
		currentZerosIndex: int | None = None

		for i in range(len(segments) + 1):		# +1 so if there is a zero-string at the end, it can still have effect on max values (as it will be forced into the elif branch)
			if i < len(segments) and segments[i] == 0:	# i < end enables use of +1 above while preventing reading of a value after end
				currentZeros += 1
				if currentZerosIndex == None:
					currentZerosIndex = i
			elif currentZeros > 0:
				if currentZeros > maxZeros:
					maxZeros = currentZeros
					maxZerosIndex = currentZerosIndex
				currentZeros = 0
				currentZerosIndex = None

		return (maxZerosIndex, maxZeros)
	
	@staticmethod
	def _toHex(numbers: Iterable[int]) -> Iterable[str]:
		return [hex(x).removeprefix("0x") for x in numbers]
			
	def _getCompressed(self, dual: bool) -> str:
		end = 8 if not dual else 6
		segments = self._segments[:end]

		zeroPadIndex, zeroPadLength = IPv6_Address.findLongestZeroSegmentString(segments)
		if zeroPadIndex == None or zeroPadLength < 2:
			return ":".join(IPv6_Address._toHex(segments))
		
		left = ":".join(IPv6_Address._toHex(segments[:zeroPadIndex]))
		right = ":".join(IPv6_Address._toHex(segments[zeroPadIndex+zeroPadLength:]))

		if len(left) > 0 and len(right) > 0:
			return left + "::" + right
		else:
			if len(left) == 0:
				return "::" + right
			else:	# len(right) == 0
				return left + "::"
			
	
	def _getFull(self, dual: bool) -> str:
		end = 8 if not dual else 6
		return ":".join([hex(x).removeprefix("0x").rjust(4, "0") for x in self._segments[: end + 1]])

	def toString(self, compressed: bool = True, uppercase: bool = True, dualOutputMode: DualOutputMode = DualOutputMode.VALUE_DEPENDENT) -> str:
		outDual = self.dual and dualOutputMode == DualOutputMode.VALUE_DEPENDENT or dualOutputMode == DualOutputMode.FORCE_DUAL
		result = self._getCompressed(outDual) if compressed else self._getFull(outDual)
		result = result.upper() if uppercase else result.lower()

		if outDual:
			if not result.endswith(":"):
				result += ":"
			result += self.ipv4.toString()

		return result
		
	def setDualAfterMerge(self, address1: Address, address2: Address) -> None:
		if type(address1) == IPv6_Address and type(address2) == IPv6_Address:
			self._dual = address1.dual and address2.dual
	
	@property
	def addressLength(self) -> int:
		return 128
	
	@property
	def addressTypeText(self) -> str:
		return "IPv6"
