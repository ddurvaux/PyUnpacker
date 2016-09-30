# This class will implement IDA support for some of his strenghts
# not yet done!! :)
#
# This is a part of the PyUnpacker package that works in IDA as a plugin
#
#
# IMPORTANT NOTE FOR MAC OS X:
# libfuzzy need to be compiled with i386 support to run in IDA (which is a 32 bit application)
# 
# To check:
# $ otool -L  /Library/Python/2.7/site-packages/ssdeep/_ssdeep_cffi_8a9054b9x627c7d55.so
#             /Library/Python/2.7/site-packages/ssdeep/_ssdeep_cffi_8a9054b9x627c7d55.so:
#   				/usr/local/lib/libfuzzy.2.dylib (compatibility version 4.0.0, current version 4.0.0)
#					/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1226.10.1)
#
# $ file /usr/local/lib/libfuzzy.2.dylib
#			/usr/local/lib/libfuzzy.2.dylib: Mach-O 64-bit dynamically linked shared library x86_64
#
# $ file /usr/lib/libSystem.B.dylib
#			/usr/lib/libSystem.B.dylib: Mach-O universal binary with 2 architectures
#			/usr/lib/libSystem.B.dylib (for architecture i386):	Mach-O dynamically linked shared library i386
#			/usr/lib/libSystem.B.dylib (for architecture x86_64):	Mach-O 64-bit dynamically linked shared library x86_64
#
# To compile:
# ./configure --prefix=/usr/local/
# make CXXFLAGS="-arch i386 -arch x86_64" CFLAGS="-arch i386 -arch x86_64" LDFLAGS="-arch i386 -arch x86_64"
# sudo make install
#
# Check if fixed:
# $ file /usr/local/lib/libfuzzy.2.dylib
# 		/usr/local/lib/libfuzzy.2.dylib: Mach-O universal binary with 2 architectures
# 		/usr/local/lib/libfuzzy.2.dylib (for architecture i386):	Mach-O dynamically linked shared library i386
# 		/usr/local/lib/libfuzzy.2.dylib (for architecture x86_64):	Mach-O 64-bit dynamically linked shared library x86_64
#
# TODO: remove relative address
#
from idautils import *
from idc import *
import ssdeep
import md5
import sys

def getPerFunctionHash():
	functions = Functions()
	for function in functions:
		funcCode = getFunctionCode(function)
		ssdeepstr = ssdeep.hash(funcCode)
		md5str = md5.new(funcCode).hexdigest()
		# TODO ADD OTHER TYPE OF HASHES
		print "sub_%08x %s %s" % (function, md5str, ssdeepstr) # DEBUG

def getFunctionCode(funcAddress):
	# retrieve function code as string
	funcCodeStr = ""
	chunks = Chunks(funcAddress)
	for [start, end] in chunks:
		print ("DEBUGS CHUNK: %s -> %s" % (start, end))
		for ea in FuncItems(start):
			instrs = GetDisasm(ea)
			funcCodeStr += instrs
	return funcCodeStr

def main():
	print "IDA PYTHON PLUGIN STARTED!!"
	print "DEBUG: %s" % sys.executable
	print "%s" % sys.path

	# TEST
	getPerFunctionHash()


if __name__ == "__main__":
    main()

# --------------------------------------------------------------------------- #
# That's all folk ;)
# --------------------------------------------------------------------------- #