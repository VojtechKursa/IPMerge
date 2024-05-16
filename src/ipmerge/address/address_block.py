from .address import Address, prefixToMask
from .ipv4 import IPv4_Address
from .ipv6 import IPv6_Address, DualOutputMode
from .exceptions import InvalidNetworkAddressException, InvalidPrefixException, UnrecognizedAddressException



class Address_Block:
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
	def parse(string: str) -> "Address_Block":
		blockParts = string.split("/")
		address = None

		for addressType in Address_Block.addressTypes:
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

		return Address_Block(address, prefix)
	
	def toString(self, compressed: bool = True, uppercase: bool = True, dualOutputMode: DualOutputMode = DualOutputMode.VALUE_DEPENDENT) -> str:
		addressString: str
		if type(self.address) == IPv6_Address:
			addressString = self.address.toString(compressed, uppercase, dualOutputMode)
		else:
			addressString = self.address.toString()
		
		return addressString + "/" + str(self.prefix)
	
	@staticmethod
	def merge(block1: "Address_Block", block2: "Address_Block") -> "Address_Block | None":
		if type(block1.address) != type(block1.address):
			return None
		elif block1._mask == block2._mask:
			if block1.address == block2.address:
				if type(block1.address) == IPv6_Address:
					block1.address.setDualAfterMerge(block1.address, block2.address)
				return Address_Block(block1.address, block1.prefix)
			
			lower = None

			if block1.lastAddress == block2.firstAddress - 1:
				lower = block1
			elif block2.lastAddress == block1.firstAddress - 1:
				lower = block2

			if lower != None and (lower.address.addressInt & ~(lower._mask << 1) == 0):
				if type(lower.address) == IPv6_Address:
					lower.address.setDualAfterMerge(block1.address, block2.address)
				return Address_Block(lower.address, lower.prefix - 1)
			else:
				return None
		elif block2.firstAddress <= block1.firstAddress and block1.lastAddress <= block2.lastAddress:
			if type(block2.address) == IPv6_Address:
				block2.address.setDualAfterMerge(block1.address, block2.address)
			return Address_Block(block2.address, block2.prefix)
		elif block1.firstAddress <= block2.firstAddress and block2.lastAddress <= block1.lastAddress:
			if type(block1.address) == IPv6_Address:
				block1.address.setDualAfterMerge(block1.address, block2.address)
			return Address_Block(block1.address, block1.prefix)
		
		return None
