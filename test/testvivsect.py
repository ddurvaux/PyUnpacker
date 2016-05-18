import sys
import os.path

# hack to load vivisect :(
sys.path.append("/Users/david/Workspace/git/vivisect")
import vivisect
import vivisect.cli as viv_cli
import vivisect.codegraph as viv_cg
import vivisect.tools.graphutil as viv_cgh

# Parameters
malbin = "./demo/upx.exe"

# Binary analysis
vw = viv_cli.VivCli()
vw.verbose = True # Enable verbose mode@

# check if workspace exists (ADD --force option?)
if(os.path.exists("%s.viv" % malbin)):
	print("FOUND an existing workspace: restoring")
	vw.loadWorkspace("%s.viv" % malbin)
else:
	vw.loadFromFile(malbin, None)
	vw.analyze() # binary analysis"
	vw.saveWorkspace() # save work

# Test -- ! need to find correctly the "main" function
for eip in vw.getEntryPoints():
	print("FOUND ENTRY POINT 0x%08x\n" % eip)
eip = vw.getEntryPoints()[0] # to replace by a call to a function for each iteration of loop
# add threading

# call the code block graph
#graph = viv_cg.CodeBlockGraph(vw)
print "GRAPH SEARCH"
#graph = vw.getFunctionGraph(eip)
graph = viv_cgh.buildFunctionGraph(vw, eip)
#graph = vw.getCallGraph()
visited = []

print("NUMBER OF NODES: %d" % len(graph.getNodes()))
for node in graph.getNodes():
	if(node in visited):
		print("LOOP DETECTED!")
		break
	else:
		visited.append(node)
	if graph.isLeafNode(node):
		print "LEAF NODE FOUND:"
		print("Set BP at: 0x%08x" % node[0])

print "THIS IS THE END :-D or :'("

#That's all folk ;)
