from .address import Address



class IPv4_Address(Address):
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
