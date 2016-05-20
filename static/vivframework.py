
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

	def __init__(self, binary, bininfo, force=False):
		self.binary = binary
		self.bininfo = bininfo
		self.force = force
		return

	def graphSearch(self):
		"""
			Do a graph search in the code for leaf nodes
		"""
		vw = viv_cli.VivCli()

		# check if workspace exists (ADD --force option?)
		if(not self.force and os.path.exists("%s.viv" % self.binary)):
			print("Found an existing workspace: restoring.  Use --force to reload the analysis.")
			vw.loadWorkspace("%s.viv" % self.binary)
		else:
			vw.loadFromFile(self.binary, None)
			vw.analyze() # binary analysis"
			vw.saveWorkspace() # save work

		# search for EIP and loop on all of them
		for eip in vw.getEntryPoints():
			print("FOUND ENTRY POINT 0x%08x\n" % eip)

			# build a code graph starting at EIP
			graph = viv_cgh.buildFunctionGraph(vw, eip)
			visited = []

			for node in graph.getNodes():
				if(node in visited):
					print("LOOP DETECTED in CODE -- ignoring path!")
					break
				else:
					visited.append(node)
				if graph.isLeafNode(node):
					# TODO print the surrounding code block
					print("TIP: Set BP at: 0x%08x" % node[0])
					self.bininfo.breakpoints.append(node[0])

		return

	def searchVirtualAlloc(self):
		"""
			VirualAllocEx
			ZwAllocateVirtualMemory
		"""
		print("NOT IMPLEMENTED")
		return


	def isJumpFar():
		"""
			Try to detect if the jump looks like a jump into deobfuscated memory area
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

	def isAntiDebug():
		"""
			sDebuggerPresent
		"""
		print("NOT IMPLEMENTED")
		return