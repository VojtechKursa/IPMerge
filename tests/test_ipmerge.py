from pathlib import Path
from ipmerge.ipmerge import merge, printOutput, readInput


class Test_IPMerge:
	def test_merge(self, tmp_path: Path):
		file = str(tmp_path) + "/file.txt"

		testInput = """
		# comment
0.0.0.1
		0.0.0.2/32 # 4
		0.0.0.2/32
	0.0.0.0 /   30   
	  
0.0.0.4 /30   
::0.0.0.0/120
::0.0.1.0/120
0.0.0.8/29
FF80::/32
FF80:1::/32

"""

		expectedResult = """0.0.0.0/28



::0.0.0.0/119
FF80::/31
"""

		with open(file, "w") as writer:
			writer.write(testInput)
		
		blocks = readInput([file])
		merge(blocks)

		outFile = str(tmp_path) + "/out.txt"
		with open(outFile, "w") as writer:
			printOutput(writer, blocks)
		
		result = ""
		with open(outFile, "r") as reader:
			result = "".join(reader.readlines())
		
		print("Expected result:")
		print(expectedResult)
		print()
		print("Actual result:")
		print(result)

		assert result == expectedResult
