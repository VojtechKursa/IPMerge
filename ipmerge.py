from pathlib import Path
from sys import argv, stderr, stdin, stdout
from os import mkdir
from typing import TextIO

from address import IP_Block



class _ProgramParameters:
	_instance = None

	def __init__(self, verbosityLevel: int = 0, outputFile: str | None = None, inputFiles : list[str] = list[str]()):
		self._verbosityLevel = verbosityLevel
		self._outputFile = outputFile
		self._inputFiles = inputFiles
	
	@property
	def verbosityLevel(self):
		return self._verbosityLevel
	
	@property
	def outputFile(self):
		return self._outputFile
	
	@property
	def inputFiles(self):
		return self._inputFiles

	@staticmethod
	def setInstance(instance: "_ProgramParameters") -> None:
		_ProgramParameters._instance = instance

	@staticmethod
	def getInstance() -> "_ProgramParameters":
		if _ProgramParameters._instance is None:
			_ProgramParameters._instance = _ProgramParameters()
		
		return _ProgramParameters._instance
	
class _ProgramParametersBuilder:
	def __init__(self):
		parameters = _ProgramParameters()

		self.verbosityLevel = parameters.verbosityLevel
		self.outputFile = parameters.outputFile
		self.inputFiles = parameters.inputFiles
	
	def create(self) -> _ProgramParameters:
		return _ProgramParameters(self.verbosityLevel, self.outputFile, self.inputFiles)



def _printUsage():
	print(f"Usage: python {Path(__file__).name} [OPTIONS] INPUT_FILES...")
	print("  INPUT_FILES - Files containing the CIDR blocks to be read and processed.")
	print("                Use '-' to read from stdin.")

def _printHelp():
	_printUsage()
	print()
	print("Options:")
	print("  -o, --output FILE    Output the result to the specified FILE instead of the terminal.")
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



def _parseParameters(arguments: list[str]) -> _ProgramParameters:
	parameters = _ProgramParametersBuilder()

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

	return parameters.create()





def readInput(fileNames : list[str]) -> dict[type, list[IP_Block]]:
	blocks = dict[type, list[IP_Block]]()

	for fileName in fileNames:
		inputFile: TextIO = stdin if fileName == "-" else open(fileName, "rt")
		
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

		if inputFile != stdin:
			inputFile.close()
	
	return blocks

def merge(blockLists: dict[type, list[IP_Block]]) -> None:
	verbosityLevel = _ProgramParameters.getInstance().verbosityLevel

	for blocks in blockLists.values():
		blocks.sort(key=lambda block: block.address.addressInt)

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
	_ProgramParameters.setInstance(_parseParameters(argv))
	parameters = _ProgramParameters.getInstance()

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
