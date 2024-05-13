from abc import abstractmethod
from pathlib import Path
from sys import argv, stderr, stdout
from os import mkdir
from typing import TextIO



class ProgramParameters:
	_instance = None

	def __init__(self, verbosityLevel: int = 0, outputFile: str | None = None, inputFiles : list[str] = list[str]()):
		self.verbosityLevel = verbosityLevel
		self.outputFile = outputFile
		self.inputFiles = inputFiles

	@staticmethod
	def getInstance() -> "ProgramParameters":
		if ProgramParameters._instance is None:
			ProgramParameters._instance = ProgramParameters()
		
		return ProgramParameters._instance



def _printUsage():
	print("Usage: ipmerge [OPTIONS] INPUT_FILES...")

def _printHelp():
	_printUsage()
	print()
	print("Options:")
	print("  -o, --output FILE    Output the result to the specified file instead of the terminal.")
	print("                         If multiple output files are specified, only the last one is accepted.")
	print("  -v                   Print merging result summary to stderr.")
	print("  -vv                  Like -v but also prints every merged block to stderr.")
	print("  -h, --help           Print help and exit.")
	print()
	print("Input files:")
	print("- The input files contain CIDR blocks (in format [NETWORK_ADDRESS]/[PREFIX_LENGTH]).")
	print("- The '/[PREFIX_LENGTH]' is optional and if missing, it is assumed that the IP is a host IP,")
	print("    therefore a block with the maximum allowable prefix length (32 for IPv4).")
	print("- Program exits with a failure if a network address invalid for the given prefix is encountered.")
	print("- The '#' character serves as a line comment, anything on the line after it is ignored.")
	print("- Empty lines are ignored.")



def _parseParameters(arguments: list[str]) -> ProgramParameters:
	parameters = ProgramParameters.getInstance()

	if len(arguments) < 2:
		_printUsage()
		exit(1)

	i = 1

	while i < len(arguments):
		argument = arguments[i]

		if argument == "-o" or argument == "--output":
			if i + 1 < len(arguments):
				parameters.outputFile = arguments[i + 1]
				i += 1
			else:
				stderr.write("Output option found, but output file doesn't follow.\n")
				exit(1)
		elif argument == "-v":
			parameters.verbosityLevel = max(parameters.verbosityLevel, 1)
		elif argument == "-vv":
			parameters.verbosityLevel = max(parameters.verbosityLevel, 2)
		elif argument == "-h" or argument == "--help":
			_printHelp()
			exit(0)
		else:
			parameters.inputFiles.append(argument)

		i += 1

	return parameters



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
		stderr.write(f"Invalid prefix {prefix}\n")
		exit(1)
	
	masks = _masksForPrefixes.get(maxPrefix)

	if masks == None:
		masks = generateMasks(maxPrefix)
		_masksForPrefixes[maxPrefix] = masks
	
	if prefix > len(masks):
		stderr.write(f"Invalid prefix {prefix} for address with maximum prefix of {maxPrefix}\n")
		exit(1)

	return masks[prefix]



class IP_Address:
	def __init__(self, address: int):
		self.address = address

	@abstractmethod
	def __str__(self) -> str:
		pass
	
	@staticmethod
	@abstractmethod
	def parse(string: str) -> "IP_Address | None":
		pass

	@staticmethod
	@abstractmethod
	def getAddressLength() -> int:
		pass

	@staticmethod
	@abstractmethod
	def getAddressTypeText() -> str:
		pass

class IPv4_Address(IP_Address):
	_inversionMask = None

	def __init__(self, address: int):
		super().__init__(address)

	def __str__(self) -> str:
		octets = list[str]()
		mask = 0xff << 24

		for i in range(4):
			octets.append(str((self.address & mask) >> ((3 - i) * 8)))
			mask >>= 8

		return ".".join(octets)
	
	@staticmethod
	def parse(string: str) -> "IPv4_Address | None":
		octets = string.split(".")

		if len(octets) != 4:
			return None
		
		address = 0

		for octet in octets:
			octetInt = int(octet)

			if(octetInt < 0 or octetInt > 255):
				return None
			else:
				address = (address << 8) | octetInt
		
		return IPv4_Address(address)
	
	@staticmethod
	def getAddressLength() -> int:
		return 32
	
	@staticmethod
	def getAddressTypeText() -> str:
		return "IPv4"



class IP_Block:
	addressTypes = {IPv4_Address}

	def __init__(self, address: IP_Address, prefix : int):
		self.address = address
		self.prefix = prefix
		self.mask = prefixToMask(address.getAddressLength(), prefix)

	def __str__(self) -> str:
		return f"{self.address}/{self.prefix}"

	@staticmethod
	def parse(string: str) -> "IP_Block":
		blockParts = string.split("/")
		address = None

		for addressType in IP_Block.addressTypes:
			address = addressType.parse(blockParts[0])
			if address != None:
				break

		if address == None:
			stderr.write(f"Unrecognized address: {blockParts[0]}\n")
			exit(1)
		
		prefix = None
		if len(blockParts) < 2:
			prefix = address.getAddressLength()
		else:
			prefix = int(blockParts[1])
			if prefix < 0 or prefix > address.getAddressLength():
				stderr.write(f"Invalid prefix {prefix} for address of type {address.getAddressTypeText()}\n")
				exit(1)

		return IP_Block(address, prefix)
	
	def getFirstAddress(self) -> int:
		return self.address.address

	def getLastAddress(self) -> int:
		return self.address.address | ((1 << (self.address.getAddressLength() - self.prefix)) - 1)
	
	@staticmethod
	def merge(block1: "IP_Block", block2: "IP_Block") -> "IP_Block | None":
		if type(block1.address) != type(block1.address):
			return None
		elif block1.mask == block2.mask:
			if block1.address == block2.address:
				return IP_Block(block1.address, block1.prefix)
			
			lower = None

			if block1.getLastAddress() == block2.getFirstAddress() - 1:
				lower = block1
			elif block2.getLastAddress() == block1.getFirstAddress() - 1:
				lower = block2

			if lower != None and (lower.address.address & ~(lower.mask << 1) == 0):
				return IP_Block(lower.address, lower.prefix - 1)
			else:
				return None
		elif block2.getFirstAddress() < block1.getFirstAddress() and block1.getLastAddress() < block2.getLastAddress():
			return IP_Block(block2.address, block2.prefix)
		elif block1.getFirstAddress() < block2.getFirstAddress() and block2.getLastAddress() < block1.getLastAddress():
			return IP_Block(block1.address, block1.prefix)
		
		return None





def readInput(fileNames : list[str]) -> dict[type, list[IP_Block]]:
	blocks = dict[type, list[IP_Block]]()

	for fileName in fileNames:
		with open(fileName, "rt") as inputFile:
			for line in inputFile:
				line = line.split("#")[0]
				if len(line.strip()) == 0:
					continue

				block = IP_Block.parse(line)

				blocksOfType = blocks.get(type(block.address))
				if blocksOfType == None:
					blocksOfType = list[IP_Block]()
					blocks[type(block.address)] = blocksOfType

				blocksOfType.append(block)
	
	return blocks

def merge(blockLists: dict[type, list[IP_Block]]) -> None:
	verbosityLevel = ProgramParameters.getInstance().verbosityLevel

	for blocks in blockLists.values():
		blocks.sort(key=lambda block: block.address.address)

		index = 1

		while index < len(blocks):
			merged = IP_Block.merge(blocks[index - 1], blocks[index])

			if merged == None:
				index += 1
			else:
				if verbosityLevel >= 2:
					stderr.write(f"Merged {blocks[index - 1]} and {blocks[index]} into {merged}.\n")

				index -= 1
				blocks.pop(index)
				blocks.pop(index)
				blocks.insert(index, merged)

				if index == 0:
					index = 1

def printOutput(output: TextIO, blockLists: dict[type, list[IP_Block]]) -> None:
	for i, blocks in enumerate(blockLists.values()):
		for block in blocks:
			output.write(block.__str__())
			output.write("\n")
		
		if i < len(blockLists) - 1:
			output.write("\n\n\n")



def main():
	_parseParameters(argv)
	parameters = ProgramParameters.getInstance()

	blocks = readInput(parameters.inputFiles)
	
	originalBlockCount = 0
	for block in blocks.values():
		originalBlockCount += len(block)
	
	merge(blocks)

	if parameters.outputFile == None:
		printOutput(stdout, blocks)
	else:
		outFolder = Path(parameters.outputFile).parent
		if not outFolder.exists():
			mkdir(outFolder)
		
		with open(parameters.outputFile, "wt") as outFile:
			printOutput(outFile, blocks)
	
	if parameters.verbosityLevel >= 1:
		currentSize = 0
		for block in blocks.values():
			currentSize += len(block)
		
		if parameters.verbosityLevel >= 2:
			stderr.write("\n")
		
		stderr.write(f"Original block count: {originalBlockCount}.\n")
		stderr.write(f"Merged block count: {currentSize} ({round(currentSize / float(originalBlockCount) * 100, 2)} %).\n")
		stderr.write(f"Decrease by: {originalBlockCount - currentSize} ({round((originalBlockCount - currentSize) / float(originalBlockCount) * 100, 2)} %).\n")





if __name__ == '__main__':
	main()
