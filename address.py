from abc import abstractmethod
from ipaddress import ip_address, IPv4Address, IPv6Address

from exceptions import InvalidNetworkAddressException, InvalidPrefixException, UnrecognizedAddressException



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



class Address:
	def __init__(self, addressInt: int):
		self.addressInt = addressInt

	def __str__(self) -> str:
		return self.compressed
	
	@staticmethod
	@abstractmethod
	def parse(string: str) -> "Address | None":
		pass

	@property
	@abstractmethod
	def compressed(self) -> str:
		pass

	@property
	@abstractmethod
	def exploded(self) -> str:
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
	def __init__(self, ip_address: IPv4Address | IPv6Address):
		super().__init__(ip_address.__int__())
		self._ip_address = ip_address

	@property
	def compressed(self) -> str:
		return self._ip_address.compressed
	
	@property
	def exploded(self) -> str:
		return self._ip_address.exploded
	
	@property
	def addressLength(self) -> int:
		return self._ip_address.max_prefixlen

class IPv4_Address(IP_Address):
	def __init__(self, address: IPv4Address):
		super().__init__(address)
		self._address = address

	@property
	def address(self) -> IPv4Address:
		return self._address
	
	@staticmethod
	def parse(string: str) -> "IPv4_Address | None":
		try:
			address = ip_address(string)
		except ValueError:
			return None
		return IPv4_Address(address) if type(address) == IPv4Address else None
	
	@property
	def addressTypeText(self) -> str:
		return "IPv4"
	
class IPv6_Address(IP_Address):
	def __init__(self, address: IPv6Address):
		super().__init__(address)
		self._address = address

	@property
	def address(self) -> IPv6Address:
		return self._address
	
	@staticmethod
	def parse(string: str) -> "IPv6_Address | None":
		try:
			address = ip_address(string)
		except ValueError:
			return None
		return IPv6_Address(address) if type(address) == IPv6Address else None
	
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

	@property
	def compressed(self) -> str:
		return f"{self.address.compressed}/{self.prefix}"
	
	@property
	def exploded(self) -> str:
		return f"{self.address.exploded}/{self.prefix}"

	def __str__(self) -> str:
		return self.compressed

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
	
	@staticmethod
	def merge(block1: "IP_Block", block2: "IP_Block") -> "IP_Block | None":
		if type(block1.address) != type(block1.address):
			return None
		elif block1._mask == block2._mask:
			if block1.address == block2.address:
				return IP_Block(block1.address, block1.prefix)
			
			lower = None

			if block1.lastAddress == block2.firstAddress - 1:
				lower = block1
			elif block2.lastAddress == block1.firstAddress - 1:
				lower = block2

			if lower != None and (lower.address.addressInt & ~(lower._mask << 1) == 0):
				return IP_Block(lower.address, lower.prefix - 1)
			else:
				return None
		elif block2.firstAddress < block1.firstAddress and block1.lastAddress < block2.lastAddress:
			return IP_Block(block2.address, block2.prefix)
		elif block1.firstAddress < block2.firstAddress and block2.lastAddress < block1.lastAddress:
			return IP_Block(block1.address, block1.prefix)
		
		return None
