from abc import abstractmethod
from math import ceil
from typing import Iterable, SupportsBytes, SupportsIndex, SupportsInt, overload

from exceptions import InvalidNetworkAddressException, InvalidPrefixException, UnrecognizedAddressException
from enum import Enum



_masksForPrefixes = dict[int, list[int]]()



def generateMasks(maxPrefix: int) -> list[int]:
	masks = list[int]()

	if maxPrefix >= 0:
		masks.append(0)
	
	for i in range(1, maxPrefix + 1):
		masks.append(masks[i - 1] | (1 << (maxPrefix - i)))

	return masks

def prefixToMask(maxPrefix: int, prefix: int) -> int:
	if prefix < 0:
		raise InvalidPrefixException(prefix)
	
	masks = _masksForPrefixes.get(maxPrefix)

	if masks == None:
		masks = generateMasks(maxPrefix)
		_masksForPrefixes[maxPrefix] = masks
	
	if prefix > len(masks):
		raise InvalidPrefixException(prefix, maxPrefix)

	return masks[prefix]



class Address(SupportsInt, SupportsBytes):
	def __init__(self, addressInt: int):
		self._addressInt = addressInt

	def __int__(self) -> int:
		return self.addressInt
	
	def __bytes__(self) -> bytes:
		return self.addressInt.to_bytes(length=ceil(self.addressLength / 8), byteorder='big', signed=False)
	
	def __str__(self) -> str:
		return self.toString()

	def __eq__(self, other: object) -> bool:
		if type(other) == type(self):
			return self.addressInt == other.addressInt
		else:
			return False

	@property
	def addressInt(self):
		return self._addressInt
	
	@abstractmethod
	def toString(self) -> str:
		pass
		
	@staticmethod
	@abstractmethod
	def parse(string: str) -> "Address | None":
		pass
	
	@property
	@abstractmethod
	def addressLength(self) -> int:
		pass

	@property
	@abstractmethod
	def addressTypeText(self) -> str:
		pass



class IP_Address(Address):
	def __init__(self, addressInt: int):
		super().__init__(addressInt)



class IPv4_Address(IP_Address):
	def __init__(self, address: int):
		super().__init__(address)
	
	@staticmethod
	def parse(string: str) -> "IPv4_Address | None":
		octets = string.split(".")
		
		if len(octets) != 4:
			return None
		
		address = 0
		for i in range(len(octets)):
			try:
				octet = int(octets[i])
			except ValueError:
				return None
			if octet < 0 or octet > 255:
				return None
			
			address |= octet << ((4 - i - 1) * 8)
		
		return IPv4_Address(address)
	
	def toString(self) -> str:
		return ".".join([str(byte) for byte in self.__bytes__()])

	@property
	def addressLength(self) -> int:
		return 32
	
	@property
	def addressTypeText(self) -> str:
		return "IPv4"



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
		return ValueError(f"Value {value} is outside of allowed range for IPv6 segment values (0 - 0xffff)")
	
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
	



class IPv6_Address(IP_Address):
	def __init__(self, address: int | IPv6Segments, dual: bool = False):
		if type(address) == int:
			super().__init__(address)
			self.__segments = IPv6Segments(address)
		elif type(address) == IPv6Segments:
			super().__init__(int(address))
			self.__segments = address

		self.__dual = dual
	
	@property
	def dual(self):
		return self.__dual
	
	@property
	def ipv4_part(self):
		return self.addressInt & 0xffffffff
	
	@property
	def ipv4(self):
		return IPv4_Address(self.ipv4_part)
	
	@property
	def string(self):
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
	def __toHex(numbers: Iterable[int]) -> Iterable[str]:
		return [hex(x).removeprefix("0x") for x in numbers]
			
	def __getCompressed(self, dual: bool) -> str:
		end = 8 if not dual else 6
		segments = self.__segments[:end]

		zeroPadIndex, zeroPadLength = IPv6_Address.findLongestZeroSegmentString(segments)
		if zeroPadIndex == None or zeroPadLength < 2:
			return ":".join(IPv6_Address.__toHex(segments))
		
		left = ":".join(IPv6_Address.__toHex(segments[:zeroPadIndex]))
		right = ":".join(IPv6_Address.__toHex(segments[zeroPadIndex+zeroPadLength:]))

		if len(left) > 0 and len(right) > 0:
			return left + "::" + right
		else:
			if len(left) == 0:
				return "::" + right
			else:	# len(right) == 0
				return left + "::"
			
	
	def __getFull(self, dual: bool) -> str:
		end = 8 if not dual else 6
		return ":".join([hex(x).removeprefix("0x").rjust(4, "0") for x in self.__segments[: end + 1]])

	def toString(self, compressed: bool = True, uppercase: bool = True, dualOutputMode: DualOutputMode = DualOutputMode.VALUE_DEPENDENT) -> str:
		outDual = self.__dual and dualOutputMode == DualOutputMode.VALUE_DEPENDENT or dualOutputMode == DualOutputMode.FORCE_DUAL
		result = self.__getCompressed(outDual) if compressed else self.__getFull(outDual)
		result = result.upper() if uppercase else result.lower()

		if outDual:
			if not result.endswith(":"):
				result += ":"
			result += self.ipv4.toString()

		return result
		
	def setDualAfterMerge(self, address1: Address, address2: Address) -> None:
		if type(address1) == IPv6_Address and type(address2) == IPv6_Address:
			self.__dual = address1.dual and address2.dual
	
	@property
	def addressLength(self) -> int:
		return 128
	
	@property
	def addressTypeText(self) -> str:
		return "IPv6"



class IP_Block:
	addressTypes: set[type[Address]] = {IPv4_Address, IPv6_Address}

	def __init__(self, address: Address, prefix : int):
		self._address = address
		self._prefix = prefix
		self._mask = prefixToMask(address.addressLength, prefix)

		if (self._address.addressInt & (~self._mask)) != 0:		# network address isn't valid network address for the given prefix
			raise InvalidNetworkAddressException(self._address.__str__(), self._prefix)
	
	@property
	def address(self):
		return self._address
	
	@property
	def prefix(self):
		return self._prefix
	
	@property
	def firstAddress(self) -> int:
		return self.address.addressInt

	@property
	def lastAddress(self) -> int:
		return self.address.addressInt | ((1 << (self.address.addressLength - self.prefix)) - 1)

	def __str__(self) -> str:
		return self.toString()

	@staticmethod
	def parse(string: str) -> "IP_Block":
		blockParts = string.split("/")
		address = None

		for addressType in IP_Block.addressTypes:
			address = addressType.parse(blockParts[0])
			if address != None:
				break

		if address == None:
			raise UnrecognizedAddressException(string)
		
		prefix = None
		if len(blockParts) < 2:
			prefix = address.addressLength
		else:
			prefix = int(blockParts[1])
			if prefix < 0 or prefix > address.addressLength:
				raise InvalidPrefixException(prefix, address.addressLength, address.addressTypeText)

		return IP_Block(address, prefix)
	
	def toString(self, compressed: bool = True, uppercase: bool = True, dualOutputMode: DualOutputMode = DualOutputMode.VALUE_DEPENDENT) -> str:
		addressString: str
		if type(self.address) == IPv6_Address:
			addressString = self.address.toString(compressed, uppercase, dualOutputMode)
		else:
			addressString = self.address.toString()
		
		return addressString + "/" + str(self.prefix)
	
	@staticmethod
	def merge(block1: "IP_Block", block2: "IP_Block") -> "IP_Block | None":
		if type(block1.address) != type(block1.address):
			return None
		elif block1._mask == block2._mask:
			if block1.address == block2.address:
				if type(block1.address) == IPv6_Address:
					block1.address.setDualAfterMerge(block1.address, block2.address)
				return IP_Block(block1.address, block1.prefix)
			
			lower = None

			if block1.lastAddress == block2.firstAddress - 1:
				lower = block1
			elif block2.lastAddress == block1.firstAddress - 1:
				lower = block2

			if lower != None and (lower.address.addressInt & ~(lower._mask << 1) == 0):
				if type(lower.address) == IPv6_Address:
					lower.address.setDualAfterMerge(block1.address, block2.address)
				return IP_Block(lower.address, lower.prefix - 1)
			else:
				return None
		elif block2.firstAddress <= block1.firstAddress and block1.lastAddress <= block2.lastAddress:
			if type(block2.address) == IPv6_Address:
				block2.address.setDualAfterMerge(block1.address, block2.address)
			return IP_Block(block2.address, block2.prefix)
		elif block1.firstAddress <= block2.firstAddress and block2.lastAddress <= block1.lastAddress:
			if type(block1.address) == IPv6_Address:
				block1.address.setDualAfterMerge(block1.address, block2.address)
			return IP_Block(block1.address, block1.prefix)
		
		return None
