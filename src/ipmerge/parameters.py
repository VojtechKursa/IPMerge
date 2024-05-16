from address.ipv6 import DualOutputMode



class IPMergeProgramParameters:
	_instance = None
	
	MAX_VERBOSITY = 2

	def __init__(self, verbosityLevel: int = 0, outputFile: str | None = None, inputFiles : list[str] = list[str](), uppercase: bool = True, compressed: bool = True, dualOutputMode: DualOutputMode = DualOutputMode.VALUE_DEPENDENT):
		self._verbosityLevel = verbosityLevel
		self._outputFile = outputFile
		self._inputFiles = inputFiles
		self._uppercase = uppercase
		self._compressed = compressed
		self._dualOutputMode = dualOutputMode
	
	@property
	def verbosityLevel(self):
		return self._verbosityLevel
	
	@property
	def outputFile(self):
		return self._outputFile
	
	@property
	def inputFiles(self):
		return self._inputFiles
	
	@property
	def uppercase(self):
		return self._uppercase
	
	@property
	def compressed(self):
		return self._compressed
	
	@property
	def dualOutputMode(self):
		return self._dualOutputMode

	@staticmethod
	def setInstance(instance: "IPMergeProgramParameters") -> None:
		IPMergeProgramParameters._instance = instance

	@staticmethod
	def getInstance() -> "IPMergeProgramParameters":
		if IPMergeProgramParameters._instance is None:
			IPMergeProgramParameters._instance = IPMergeProgramParameters()
		
		return IPMergeProgramParameters._instance



class IPMergeProgramParametersBuilder:
	def __init__(self):
		parameters = IPMergeProgramParameters()

		self.verbosityLevel = parameters.verbosityLevel
		self.outputFile = parameters.outputFile
		self.inputFiles = parameters.inputFiles
		self.uppercase = parameters.uppercase
		self.compressed = parameters.compressed
		self.dualOutputMode = parameters.dualOutputMode
	
	def create(self) -> IPMergeProgramParameters:
		return IPMergeProgramParameters(self.verbosityLevel, self.outputFile, self.inputFiles, self.uppercase, self.compressed, self.dualOutputMode)
