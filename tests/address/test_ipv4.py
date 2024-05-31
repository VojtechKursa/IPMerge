from ipmerge.address.ipv4 import IPv4_Address

class Test_IPv4:
	def test_parse_ok(self):
		assert IPv4_Address.parse("0.0.0.0") == IPv4_Address(0)
		assert IPv4_Address.parse("255.255.255.255") == IPv4_Address(2 ** 32 - 1)
		assert IPv4_Address.parse("192.168.0.1") == IPv4_Address(0xC0A80001)
		assert IPv4_Address.parse("0.0.0.1") == IPv4_Address(1)
		assert IPv4_Address.parse("1.0.0.0") == IPv4_Address(0x1000000)
	
	def test_parse_fail(self):
		assert IPv4_Address.parse("0") == None
		assert IPv4_Address.parse("-1") == None
		assert IPv4_Address.parse("a") == None

		assert IPv4_Address.parse("") == None

		assert IPv4_Address.parse("1.1.1.1.1") == None
		assert IPv4_Address.parse("1.1.1.1 1") == None

		assert IPv4_Address.parse("a.a.a.a") == None
		assert IPv4_Address.parse("-1.-1.-1.-1") == None
		assert IPv4_Address.parse("256.256.256.265") == None

	def test_stringify(self):
		inputs = (
			"0.0.0.0",
			"1.1.1.1",
			"255.255.255.255",
			"10.0.0.0",
			"10.0.0.1",
			"192.168.0.1",
			"0.0.0.1",
			"1.0.0.0"
		)

		for input in inputs:
			print("Testing", input, "...", flush=True, end="")
			address = IPv4_Address.parse(input)
			assert type(address) == IPv4_Address
			assert address.toString() == input
			print("OK")

