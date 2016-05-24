
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
					print("TIP: Set BP at: 0x%08x (%s)" % (node[0], self.vw.reprVa(node[0])))
					refby = self.vw.getXrefsTo(node[0])
					for ref in refby:
						print("    REFERENCED at:  0x%08x (%s)" % (ref[0], self.vw.reprVa(ref[0])))
						self.getFunctionCode(ref[0])
					self.bininfo.breakpoints.append(node[0])

			#TODO: add check if instruction is JMP + destination
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


	def isJumpFar(self):
		"""
			Try to detect if the jump looks like a jump into deobfuscated memory area

			Play with memory map
		"""
		print("NOT IMPLEMENTED")
		return

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
		print("NOT IMPLEMENTED")
		return

	def getFunctionCode(self, va):
		"""
			Not working - gives back code after
			BUGGY!!
		"""
		codeblock = self.vw.getCodeBlock(va)
		blocks = self.vw.getFunctionBlocks(codeblock[0])
		for block in blocks:
			print("CODE BLOCK: %s" % self.vw.reprVa(block[0]))
		print("NOT IMPLEMENTED")
		return