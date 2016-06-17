
# temporary hack - to be fixed
import sys
sys.path.append("/Users/david/Workspace/git/vivisect")

# import vivisect framework
import vivisect
import vivisect.cli as viv_cli
import vivisect.codegraph as viv_cg
import vivisect.tools.graphutil as viv_cgh

# import other libraries
import os
import hashlib

class Vivisect:
	binary = None
	bininfo = None
	force = False
	vw = None

	def __init__(self, binary, bininfo, force=False):
		self.binary = binary
		self.bininfo = bininfo
		self.force = force

		# initialize Vivisect Framework
		self.vw = viv_cli.VivCli()

		# check if workspace exists (ADD --force option?)
		if(not self.force and os.path.exists("%s.viv" % self.binary)):
			print("Found an existing workspace: restoring.  Use --force to reload the analysis.")
			self.vw.loadWorkspace("%s.viv" % self.binary)
		else:
			self.vw.loadFromFile(self.binary, None)
			self.vw.analyze() # binary analysis"
			self.vw.saveWorkspace() # save work

		# done
		return

	def graphSearch(self):
		"""
			Do a graph search in the code for leaf nodes

			TODO: check if detected instruction is a jump!
		"""
		# search for EIP and loop on all of them
		for eip in self.vw.getEntryPoints():
			print("FOUND ENTRY POINT 0x%08x\n" % eip)

			# build a code graph starting at EIP
			graph = viv_cgh.buildFunctionGraph(self.vw, eip)
			visited = []

			for node in graph.getNodes():
				if(node in visited):
					print("LOOP DETECTED in CODE -- ignoring path!")
					break
				else:
					visited.append(node)
				if graph.isLeafNode(node):
					# TODO print the surrounding code block
					if self.isJumpFar(node[0]):
						print("TIP: Set BP at: 0x%08x (%s)" % (node[0], self.vw.reprVa(node[0])))
						refby = self.vw.getXrefsTo(node[0])
						for ref in refby:
							print("    REFERENCED at:  0x%08x (%s)" % (ref[0], self.vw.reprVa(ref[0])))
							self.getFunctionCode(ref[0])
						self.bininfo.breakpoints.append(node[0])
		return

	def searchVirtualAlloc(self):
		"""
			Search for memory allocation as place where binary could be unpacked

			VirualAllocEx
			https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890(v=vs.85).aspx

			ZwAllocateVirtualMemory:
			https://msdn.microsoft.com/en-us/library/windows/hardware/ff566416(v=vs.85).aspx
		"""
		virtualAllocEx = self.vw.getImportCallers('winapi.VirtualAllocEx')
		zwAllocateVirtMem = self.vw.getImportCallers('ntoskrnl.ZwAllocateVirtualMemory')
		print("DEBUG: VirtualAllocEx: %d ZwAllocateVirtualMemory: %d" % (len(virtualAllocEx), len(zwAllocateVirtMem)))

		print("NOT YET FULLY IMPLEMENTED!")
		return


	def isJumpFar(self, destaddr):
		"""
			Try to detect if the jump looks like a jump into deobfuscated memory area

			TODO:
				- keep the memory zone somewhere to speed up process
				- enhance detection (naive implementation right now)

		"""
		segments = self.vw.getSegments() # show section in code.... not the goal
		for [segaddr, segsize, segloc, segname] in segments:
			segend = segaddr + segsize
			if( (segaddr <= destaddr) and (destaddr <= segend)):
				return False
			#print("DEBUG SEGMENT INFO: 0x%08x -> 0x%08x size:%d (%s %s)" % (segaddr, segend, segsize, segloc, segname))
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
		# check for isDebbugerPresent()
		debugPresent = self.vw.getImportCallers('winapi.IsDebuggerPresent')
		if(len(debugPresent) > 0):
			print("isDebuggerPresent() found")
			self.bininfo.anti_debug = True
		return self.bininfo.anti_debug

	def getPerFunctionHash(self):

		for fva in self.vw.getFunctions():
			fcode = self.getFunctionCode(fva)
			ccode = self.__clean_code__(fcode)
			fhash = self.__make_hash__(ccode)
			print("FUNCTION 0x%08x --> %s" % (fva, fhash))
			#  -- HERE compute hash -- 

		# get the list of functions then loop on each to 
		# compute SSDEEP and alternate methods
		# after cleaning offsets and non relative addresses
		# --> make a tool class for this

		print("NOT IMPLEMENTED")
		return

	def getFunctionCode(self, va):
		"""
			Not working - gives back code after
			BUGGY!!
		"""
		blocksstr = []
		codeblock = self.vw.getCodeBlock(va)
		#print("DEBUG")
		#print(codeblock)
		blocks = self.vw.getFunctionBlocks(codeblock[0])
		for block in blocks:
			blocksstr.append("%s" % self.vw.reprVa(block[0]))
		print("NOT IMPLEMENTED")
		return blocksstr

	def __clean_code__(self, opcodes):
		print("NOT IMPLEMENTED")
		return opcodes #DEBUG

	def __make_hash__(self, opcodes):
		"""
			TODO EXTEND + IMPROVE!
		"""
		bigstr = ""
		for block in opcodes:
			bigstr = bigstr + block
		m = hashlib.md5()
		m.update(bigstr)
		return m.hexdigest()

