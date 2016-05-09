import sys

# hack to load vivisect :(
sys.path.append("/Users/david/Workspace/git/vivisect")
import vivisect
import vivisect.cli as viv_cli
import vivisect.codegraph as viv_cg
import vivisect.tools.graphutil as viv_cgh

# Parameters
malbin = "./demo/upx.exe"

# Binary analysis
# TODO - support workspace restoration
vw = viv_cli.VivCli()
vw.verbose = True # Enable verbose mode
vw.loadFromFile(malbin, None)
vw.analyze() # binary analysis
vw.saveWorkspace() # save work


# Test -- ! need to find correctly the "main" function
for function in vw.getFunctions():
	print("%s\n" % function)
viv_cgh.buildFunctionGraph(vw, vw.getFunctions()[0])

# call the code block graph
#graph = viv_cg.CodeBlockGraph(vw)
print "GRAPH SEARCH"
graph = viv_cg.CallGraph()
print("NUMBER OF NODES: %d" % len(graph.getNodes()))
for node in graph.getNodes():
	if graph.isLeafNode(node):
		print "LEAF NODE FOUND:"
		print node

print "THIS IS THE END :-D or :'("

#That's all folk ;)
