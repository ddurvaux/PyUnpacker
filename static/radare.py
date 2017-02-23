import json
import r2pipe

class Radare2:

	"""
		import r2pipe	

		r2 = r2pipe.open("/bin/ls")
		r2.cmd('aa')
		print(r2.cmd("afl"))
		print(r2.cmdj("aflj"))  # evaluates JSONs and returns an object
	"""
	debug = False
	binary = None
	bininfo = None
	force = False
	r2 = None


	def __init__(self, binary, bininfo, force=False):
		self.binary = binary
		self.bininfo = bininfo
		self.force = force

		# open binary in Radare2 and trigger binary analysis
		self.r2 = r2pipe.open(self.binary)
		self.r2.cmd('aaa')  # analyze all referenced code

		# done
		return


	def __get_functions__(self):
		flist = self.r2.cmdj("aflj")

		if self.debug:
			print("DEBUG: List of function (JSON query / %s)=\n%s" % (type(flist), flist))
			try:
				fd = open("/Users/david/Workspace/malwares/netwars/function_list.json", "w")
				json.dump(flist, fd, sort_keys=True, indent=4, separators=(',', ': '))
				fd.close()
			except Exception as e:
				print("Impossible to save JSON file")
				print(e)

		return flist # DEBUG - CHANGEME


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


#DEBUG / TEST
def main():
	radare = Radare2("/Users/david/Workspace/malwares/netwars/b.exe", None)
	functions = radare.__get_functions__()
	for function in functions:
		fname = function["name"]
		print(fname)

if __name__ == "__main__":
	main()

