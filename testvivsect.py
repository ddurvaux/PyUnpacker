import sys

# hack to load vivisect :(
sys.path.append("/Users/david/Workspace/git/vivisect")
import vivisect
import vivisect.cli as viv_cli

# Binary analysis
vw = viv_cli.VivCli()
vw.verbose = True # Enable verbose mode
vw.analyze() # binary analysis
vw.saveWorkspace() # save work

