from ipmerge.address.ipv4 import IPv4_Address

def test_parse():
	assert IPv4_Address.parse("192.168.0.1") == IPv4_Address(0xC0A80001)
