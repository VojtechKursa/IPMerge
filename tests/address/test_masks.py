import pytest
from ipmerge.address.address import prefixToMask
from ipmerge.address.exceptions import InvalidPrefixException


class Test_Mask:
	def test_masks_ok(self):
		assert prefixToMask(32, 24) == 0xFFFFFF00
		assert prefixToMask(32, 0) == 0
		assert prefixToMask(32, 32) == (1 << 32) - 1

		assert prefixToMask(0, 0) == 0

	def test_masks_fail(self):
		with pytest.raises(InvalidPrefixException):
			prefixToMask(32, -1)
		with pytest.raises(InvalidPrefixException):
			prefixToMask(32, 33)
		with pytest.raises(InvalidPrefixException):
			prefixToMask(-1, 0)
