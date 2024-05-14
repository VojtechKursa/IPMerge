class InvalidPrefixException(Exception):
	def __init__(self, prefix: int, maxPrefix: int | None = None, addressType: str | None = None):
		super().__init__()
		self._prefix = prefix
		self._maxPrefix = maxPrefix
		self._addressType = addressType

	@property
	def prefix(self):
		return self._prefix
	
	@property
	def maxPrefix(self):
		return self._maxPrefix
	
	@property
	def addressType(self):
		return self._addressType
	
	def __str__(self) -> str:
		string = f"ERROR: Invalid prefix {self.prefix}"
		if self.addressType != None:
			string += f" for address of type '{self.addressType}'"
		if self.maxPrefix != None:
			string += f" where maximum prefix length is {self.maxPrefix}"
		return string + "."



class UnrecognizedAddressException(Exception):
	def __init__(self, text: str):
		super().__init__()
		self._text = text

	@property
	def text(self):
		return self._text
	
	def __str__(self) -> str:
		return f"ERROR: Unrecognized address '{self.text}'."



class InvalidNetworkAddressException(Exception):
	def __init__(self, address: str, prefix: int) -> None:
		super().__init__()
		self._address = address
		self._prefix = prefix

	@property
	def address(self):
		return self._address
	
	@property
	def prefix(self):
		return self._prefix

	def __str__(self) -> str:
		return f"ERROR: Invalid network address {self.address} for prefix {self.prefix}"
