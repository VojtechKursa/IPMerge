from pathlib import Path
from sys import argv, stderr, stdin, stdout
from os import mkdir
from typing import TextIO

from address.address_block import Address_Block
from parameters import IPMergeProgramParameters, IPMergeProgramParametersBuilder, DualOutputMode



def _printUsage():
	print(f"Usage: python {Path(__file__).name} [OPTIONS] INPUT_FILES...")
	print("  INPUT_FILES - Files containing the CIDR blocks to be read and processed.")
	print("                Use '-' to read from stdin.")

def _printHelp():
	_printUsage()
	print()
	print("Options:")
	print("  -h, --help           Print help and exit.")
	print("  -o, --output FILE    Output the result to the specified FILE instead of the terminal.")
	print("                         If multiple output files are specified, only the last one is accepted.")
	print("  -v                   Print merging result summary to stderr.")
	print("  -vv                  Like -v but also prints every merged block to stderr.")
	print("  -u, --upper          Print all letters (i.e. in IPv6 address) in uppercase (default).")
	print("  -l, --lower          Print all letters (i.e. in IPv6 address) in lowercase.")
	print("  -c, --compressed     Print addresses that allow shortening (i.e. IPv6) in shortened (compressed) format (default).")
	print("  -f, --full           Print all addresses in full (uncompressed) format.")
	print("  -p, --preserve       Print only dual IPv6 addresses in dual format and normal IPv6 addresses")
	print("                         in normal format (default). Note: When a dual IPv6 address is merged with")
	print("                         a normal IPv6 address, it becomes a normal IPv6 address.")
	print("  -d, --dual           Force printing of IPv6 addresses in dual format.")
	print("  -n, --normal         Force printing of IPv6 addresses in normal format.")
	print()
	print("Input files:")
	print("- The input files contain CIDR blocks (in format [NETWORK_ADDRESS]/[PREFIX_LENGTH]).")
	print("- The '/[PREFIX_LENGTH]' is optional and if missing, it is assumed that the IP is a host IP,")
	print("    therefore a block with the maximum allowable prefix length (32 for IPv4, 128 for IPv6, ...).")
	print("- Program exits with a failure if a network address invalid for the given prefix is encountered.")
	print("- The '#' character serves as a line comment, anything on the line after it is ignored.")
	print("- Empty lines are ignored.")
	print()
	print("Currently supported addresses:")
	print("- IPv4")
	print("- IPv6 - both normal and dual format")



def _parseParameters(arguments: list[str]) -> IPMergeProgramParameters:
	parameters = IPMergeProgramParametersBuilder()

	if len(arguments) < 2:
		_printUsage()
		exit(1)

	i = 1

	outputFollows = False

	while i < len(arguments):
		argument = arguments[i]

		if outputFollows:
			parameters.outputFile = argument
			outputFollows = False
		elif len(argument) >= 2 and argument[0] == "-":
			if argument[1] == "-":
				match argument:
					case "--help":
						_printHelp()
						exit(0)
					case "--output": outputFollows = True
					case "--upper": parameters.uppercase = True
					case "--lower": parameters.uppercase = False
					case "--compressed": parameters.compressed = True
					case "--full": parameters.compressed = False
					case "--preserve": parameters.dualOutputMode = DualOutputMode.VALUE_DEPENDENT
					case "--dual": parameters.dualOutputMode = DualOutputMode.FORCE_DUAL
					case "--normal": parameters.dualOutputMode = DualOutputMode.FORCE_NORMAL
					case _:
						stderr.write(f"Unknown option '{argument}'\n")
						exit(1)
			else:
				for charIndex in range(1, len(argument)):
					match argument[charIndex]:
						case "h":
							_printHelp()
							exit(0)
						case "o": outputFollows = True
						case "v": parameters.verbosityLevel = min(parameters.verbosityLevel + 1, IPMergeProgramParameters.MAX_VERBOSITY)
						case "u": parameters.uppercase = True
						case "l": parameters.uppercase = False
						case "c": parameters.compressed = True
						case "f": parameters.compressed = False
						case "p": parameters.dualOutputMode = DualOutputMode.VALUE_DEPENDENT
						case "d": parameters.dualOutputMode = DualOutputMode.FORCE_DUAL
						case "n": parameters.dualOutputMode = DualOutputMode.FORCE_NORMAL
						case _:
							stderr.write(f"Unknown option '{argument[charIndex]}' in '{argument}'\n")
							exit(1)
		else:
			parameters.inputFiles.append(argument)
		
		i += 1
	
	if outputFollows:
		stderr.write("Output option found, but output file doesn't follow.\n")
		exit(1)

	return parameters.create()





def readInput(fileNames : list[str]) -> dict[type, list[Address_Block]]:
	blocks = dict[type, list[Address_Block]]()

	for fileName in fileNames:
		inputFile: TextIO = stdin if fileName == "-" else open(fileName, "rt")
		
		for line in inputFile:
			line = line.split("#")[0]
			if len(line.strip()) == 0:
				continue

			block = Address_Block.parse(line)

			blocksOfType = blocks.get(type(block.address))
			if blocksOfType == None:
				blocksOfType = list[Address_Block]()
				blocks[type(block.address)] = blocksOfType

			blocksOfType.append(block)

		if inputFile != stdin:
			inputFile.close()
	
	return blocks

def merge(blockLists: dict[type, list[Address_Block]]) -> None:
	verbosityLevel = IPMergeProgramParameters.getInstance().verbosityLevel

	for blocks in blockLists.values():
		blocks.sort(key=lambda block: block.address.addressInt)

		index = 1

		while index < len(blocks):
			merged = Address_Block.merge(blocks[index - 1], blocks[index])

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

def printOutput(output: TextIO, blockLists: dict[type, list[Address_Block]]) -> None:
	parameters = IPMergeProgramParameters.getInstance()

	for i, blocks in enumerate(blockLists.values()):
		for block in blocks:
			output.write(block.toString(parameters.compressed, parameters.uppercase, parameters.dualOutputMode))
			output.write("\n")
		
		if i < len(blockLists) - 1:
			output.write("\n\n\n")





def main():
	IPMergeProgramParameters.setInstance(_parseParameters(argv))
	parameters = IPMergeProgramParameters.getInstance()

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
	try:
		main()
	except Exception as e:
		stderr.write(e.__str__())
		stderr.write("\n")
