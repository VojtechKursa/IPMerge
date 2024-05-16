from abc import abstractmethod
from math import ceil
from typing import SupportsBytes, SupportsInt

from .exceptions import InvalidPrefixException



_masksForPrefixes = dict[int, list[int]]()



def _generateMasks(maxPrefix: int) -> list[int]:
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
		masks = _generateMasks(maxPrefix)
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
