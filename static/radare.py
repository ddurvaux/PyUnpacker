
class Radare2:
	debug = True
	binary = None
	bininfo = None
	force = False



	def __init__(self, binary, bininfo, force=False):
		self.binary = binary
		self.bininfo = bininfo
		self.force = force

		# done
		return

	def graphSearch(self):
		"""
			Do a graph search in the code for leaf nodes

			TODO: check if detected instruction is a jump!
		"""
		return


	def searchVirtualAlloc(self):
		"""
			Search for memory allocation as place where binary could be unpacked

			VirualAllocEx
			https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890(v=vs.85).aspx

			ZwAllocateVirtualMemory:
			https://msdn.microsoft.com/en-us/library/windows/hardware/ff566416(v=vs.85).aspx
		"""
		return


	def isJumpFar(self, destaddr):
		"""
			Try to detect if the jump looks like a jump into deobfuscated memory area

			TODO:
				- keep the memory zone somewhere to speed up process
				- enhance detection (naive implementation right now)

		"""
		return True


	def exceptionHandler(self):
		"""
			push push mov
			Exception_Handler_Address ; The Exception Handler address is on stack large dword ptr fs:0
			large fs:0, esp
			--------- [Make Exception] -------------
			pop large dword ptr fs:0 ; remove SEH add esp, 4 ; Align Stack


		or


			RTDSC
		"""
		print("NOT IMPLEMENTED")
		return


	def isAntiDebug(self):
		"""
			Check for anti-debugging tricks
			Update bininfo.anti_debug accordinely

			TODO - add support for other tricks
		"""
		return


	def getPerFunctionHash(self):
		print("NOT IMPLEMENTED")
		return


	def getFunctionCode(self, va):
		"""
			Not working - gives back code after
			BUGGY!!
		"""
		blocksstr = []
		return blocksstr


	def __clean_code__(self, opcodes):
		print("NOT IMPLEMENTED")
		return opcodes #DEBUG


	def __make_hash__(self, opcodes):
		"""
			TODO EXTEND + IMPROVE!
		"""
		return None

