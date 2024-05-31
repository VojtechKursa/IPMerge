from ipmerge.address.ipv6 import DualOutputMode, IPv6_Address

class Test_IPv6:
	def test_parse_normal_ok(self):
		assert IPv6_Address.parse("::") == IPv6_Address(0)
		assert IPv6_Address.parse("8000::") == IPv6_Address(1 << 127)
		assert IPv6_Address.parse("::1") == IPv6_Address(1)

		assert IPv6_Address.parse("FFFF::FFFF") == IPv6_Address(0xFFFF << (128 - 16) | 0xFFFF)
		assert IPv6_Address.parse("ffff::ffff") == IPv6_Address(0xFFFF << (128 - 16) | 0xFFFF)

		assert IPv6_Address.parse("0000:0000:0000:0000:0000:0000:0000:0000") == IPv6_Address(0)
		assert IPv6_Address.parse("0:0:0:0:0:0:0:0") == IPv6_Address(0)
		assert IPv6_Address.parse("0:0:0:0:0:0::") == IPv6_Address(0)
		assert IPv6_Address.parse("8000:0000:0000:0000:0000:0000:0000:0001") == IPv6_Address((1 << 127) | 1)

		assert IPv6_Address.parse("::0001:0:1:A000:0") == IPv6_Address(0x100000001A0000000)


	def test_parse_normal_fail(self):
		assert IPv6_Address.parse(":::") == None
		assert IPv6_Address.parse("::0::") == None
		
		assert IPv6_Address.parse("") == None

		assert IPv6_Address.parse("0") == None
		assert IPv6_Address.parse("1") == None
		assert IPv6_Address.parse("-1") == None
		assert IPv6_Address.parse("a") == None

		assert IPv6_Address.parse("G::") == None
		assert IPv6_Address.parse("0:0:0:0:0:0:0:0:0") == None
		assert IPv6_Address.parse("0:0:0:0:0:0:0:0::") == None
		assert IPv6_Address.parse("0:0:0:0:0:0:0::") == None
		assert IPv6_Address.parse("10000::") == None


	def test_parse_dual_ok(self):
		temp = IPv6_Address.parse("::0.0.0.0")
		assert type(temp) == IPv6_Address
		assert temp == IPv6_Address(0)
		assert temp.dual == True

		temp = IPv6_Address.parse("::255.255.255.255")
		assert type(temp) == IPv6_Address
		assert temp == IPv6_Address(0xFFFFFFFF)
		assert temp.dual == True

		temp = IPv6_Address.parse("::128.0.0.1")
		assert type(temp) == IPv6_Address
		assert temp == IPv6_Address(0x80000001)
		assert temp.dual == True

		temp = IPv6_Address.parse("::8000:255.255.255.255")
		assert type(temp) == IPv6_Address
		assert temp == IPv6_Address(0x8000FFFFFFFF)
		assert temp.dual == True

		temp = IPv6_Address.parse("8000::255.255.255.255")
		assert type(temp) == IPv6_Address
		assert temp == IPv6_Address(1 << 127 | 0xFFFFFFFF)
		assert temp.dual == True

		temp = IPv6_Address.parse("::1:255.255.255.255")
		assert type(temp) == IPv6_Address
		assert temp == IPv6_Address(0x1FFFFFFFF)
		assert temp.dual == True
	

	def test_parse_dual_fail(self):
		assert IPv6_Address.parse("::0.0.0.0.0") == None

		assert IPv6_Address.parse("0.0.0.0") == None
		assert IPv6_Address.parse("255.255.255.255") == None

		assert IPv6_Address.parse("::256.0.0.0") == None

		assert IPv6_Address.parse("0.0.0.0:0::") == None
		assert IPv6_Address.parse("0.0.0.0::") == None
		assert IPv6_Address.parse("0:0:0:0:0:255.255.255.255:0") == None
	

	def test_stringify(self):
		class TestingParameters:
			def __init__(
					self,
					input: str,
					expectedOutput: str | None = None,
					uppercase: bool = True,
					dualOutputMode: DualOutputMode = DualOutputMode.VALUE_DEPENDENT,
					compressed: bool = True
					):
				self.input = input
				self.expectedOutput = expectedOutput if expectedOutput != None else input
				self.uppercase = uppercase
				self.dualOutputMode = dualOutputMode
				self.compressed = compressed

			def __str__(self) -> str:
				return f"{self.input} (u: {self.uppercase}, c: {self.compressed}, dom: {DualOutputMode.toString(self.dualOutputMode)}) => {self.expectedOutput}"
			
			def eval(self):
				address = IPv6_Address.parse(self.input)
				assert type(address) == IPv6_Address
				assert address.toString(uppercase=self.uppercase, compressed=self.compressed, dualOutputMode=self.dualOutputMode) == self.expectedOutput
		
		cases = (
			TestingParameters("::"),
			TestingParameters("8000::"),
			TestingParameters("::1"),
			TestingParameters("FFFF::FFFF"),
			TestingParameters("8000::1"),
			TestingParameters("FFFF::FF:0:0:0"),

			TestingParameters("::","0000:0000:0000:0000:0000:0000:0000:0000", compressed=False),
			TestingParameters("0000:0000:0000:0000:0000:0000:0000:0000", "::"),
			TestingParameters("0:0:0:0:0:0:0:0","::"),

			TestingParameters("::ffff","::FFFF"),
			TestingParameters("::FFFF","::ffff", uppercase=False),

			TestingParameters("FFFF::FFFF", "FFFF::0.0.255.255", dualOutputMode=DualOutputMode.FORCE_DUAL),
			TestingParameters("FFFF::255.255.0.255"),
			TestingParameters("FFFF::255.255.0.255", "FFFF::FFFF:FF", dualOutputMode=DualOutputMode.FORCE_NORMAL)
		)

		for i, case in enumerate(cases):
			print(f"Evaluating case {i + 1}: {case}", end="   ...", flush=True)
			case.eval()
			print("   OK")
