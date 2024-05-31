import pytest
from ipmerge.address.address_block import Address_Block
from ipmerge.address.exceptions import InvalidNetworkAddressException, InvalidPrefixException, UnrecognizedAddressException
from ipmerge.address.ipv4 import IPv4_Address
from ipmerge.address.ipv6 import IPv6_Address


class Test_AddressBlock:
	def test_parse_ok(self):
		assert Address_Block.parse("0.0.0.0/24") == Address_Block(IPv4_Address(0), 24)
		assert Address_Block.parse("0.0.0.2/31") == Address_Block(IPv4_Address(2), 31)

		assert Address_Block.parse("::/128") == Address_Block(IPv6_Address(0), 128)
		assert Address_Block.parse("::") == Address_Block(IPv6_Address(0), 128)
		assert Address_Block.parse("::/0") == Address_Block(IPv6_Address(0), 0)

		assert Address_Block.parse("::  /   0\r\n") == Address_Block(IPv6_Address(0), 0)


	def test_parse_fail(self):
		with pytest.raises(UnrecognizedAddressException):
			Address_Block.parse("/5")
		with pytest.raises(UnrecognizedAddressException):
			Address_Block.parse("")
		with pytest.raises(UnrecognizedAddressException):
			Address_Block.parse("aa/0")
		
		with pytest.raises(InvalidNetworkAddressException):
			Address_Block.parse("0.0.0.2/30")
		
		with pytest.raises(InvalidPrefixException):
			Address_Block.parse("::/129")
		with pytest.raises(InvalidPrefixException):
			Address_Block.parse("::/-1")
	
	
	def test_stringify(self):
		assert Address_Block.parse("::/128").toString() == "::"
		assert Address_Block.parse("::/128").toString(alwaysOutputPrefix=True) == "::/128"

		assert Address_Block.parse("0.0.0.0/24").toString() == "0.0.0.0/24"


	def test_merge_super(self):
		a = Address_Block.parse("0.0.0.0/24")
		b = Address_Block.parse("0.0.0.128/25")
		assert Address_Block.merge(a, b) == Address_Block.parse("0.0.0.0/24")
		assert Address_Block.merge(b, a) == Address_Block.parse("0.0.0.0/24")


	def test_merge_identical(self):
		a = Address_Block.parse("0.0.0.0/24")
		b = Address_Block.parse("0.0.0.0/24")
		assert Address_Block.merge(a, b) == Address_Block.parse("0.0.0.0/24")
		assert Address_Block.merge(b, a) == Address_Block.parse("0.0.0.0/24")
	

	def test_merge_adjacent(self):
		a = Address_Block.parse("0.0.0.0/24")
		b = Address_Block.parse("0.0.1.0/24")
		assert Address_Block.merge(a, b) == Address_Block.parse("0.0.0.0/23")
		assert Address_Block.merge(b, a) == Address_Block.parse("0.0.0.0/23")
	

	def test_merge_fail(self):
		a = Address_Block.parse("0.0.0.0/24")
		b = Address_Block.parse("0.0.2.0/24")
		assert Address_Block.merge(a, b) == None
		assert Address_Block.merge(b, a) == None

		a = Address_Block.parse("0.0.1.0/24")
		b = Address_Block.parse("0.0.2.0/24")
		assert Address_Block.merge(a, b) == None
		assert Address_Block.merge(b, a) == None

		a = Address_Block.parse("::/120")
		b = Address_Block.parse("0.0.0.0/24")
		assert Address_Block.merge(a, b) == None
		assert Address_Block.merge(b, a) == None
