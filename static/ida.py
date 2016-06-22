# This class will implement IDA support for some of his strenghts
# not yet done!! :)
#
# This is a part of the PyUnpacker package that works in IDA as a plugin
#
from idautils import *
from idc import *

def getPerFunctionHash():
	functions = Functions()
	for function in functions:
		print "sub_%08x" % function # DEBUG

def main():
	print "IDA PYTHON PLUGIN STARTED!!"
	
	# TEST
	getPerFunctionHash()


if __name__ == "__main__":
    main()

# --------------------------------------------------------------------------- #
# That's all folk ;)
# --------------------------------------------------------------------------- #