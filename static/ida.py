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
# Don't forget to re-install python-ssdeep afterward
# $ sudo python ./setup.py build
# $ sudo python ./setup.py install
#
# TODO: 
# - remove relative address (function cleanUpCode)
# - replace pickle by JSON format
#
# --------------------------------------------------------------------------- #
import os
import md5
import sys
import pickle
import ssdeep
from idc import *
from idautils import *
#from lshash import LSHasqcccfrt

debug = False
dump = True
dumpdir = "./dump"

def getPerFunctionHash():
	"""
		Iterates on program function and, for each, computes
	 	- MD5 sum
	 	- SSDEEP
	"""
	functions = Functions()
	hashes = {}
	for function in functions:
		funcCode = getFunctionCode(function)
		funcCode = cleanUpCode(function, funcCode)
		ssdeepstr = ssdeep.hash(funcCode)
		md5str = md5.new(funcCode).hexdigest()
		#lsh = LSHash(512, len(funcCode))
		#lsh.index(funcCode)
		# TODO ADD OTHER TYPE OF HASHES
		hashes[function] = {
			"md5" : md5str,
			"ssdeep" : ssdeepstr,
		}
		if debug:
			print "sub_%08x %s %s" % (function, md5str, ssdeepstr) # DEBUG

	if dump: # save hash table in dump mode
		fd = open("./%s/%s.pickle" % (dumpdir, "hashes"), "w")
		pickle.dump(hashes, fd)
		fd.close()
	return hashes


def getFunctionCode(funcAddress):
	"""
		Start from a function address
		and return function code
	"""
	# retrieve function code as string
	funcCodeStr = ""
	chunks = Chunks(funcAddress)
	for [start, end] in chunks:
		if debug:
			print ("DEBUGS CHUNK: %s -> %s" % (start, end))
		for ea in FuncItems(start):
			instrs = GetDisasm(ea)
			funcCodeStr += "%s\n" % instrs

	if dump: # save function code in dump mode
		fd = open("./%s/%s.asm" % (dumpdir, funcAddress), "w")
		fd.write(funcCodeStr)
		fd.close()

	return funcCodeStr


def cleanUpCode(funcAddress, codeStr):
	"""
		For an instruction, remove references

		Require to make intelligent comparison
		idepentetly of offset, addresses...
	"""
	# Code pattern and their generic replacement	
	patterns = {
		#    PATTERN          REPLACEMENT
		"\[\w{3}\+.*\]"    :   "[VAR]"    ,   # mov     ecx, [ebp+arg_8]
		"offset off_\d+"   :   "OFFSET"   ,   # mov     ebx, offset off_419940
		"loc_\d+"          :   "LOC"      ,   # jz      short loc_406470
		";\s+\w+(\s+\*)?"  :   ""         ,   # remove  comments
	}
	for pattern in patterns.keys():
		replacement = patterns[pattern]
		codeStr = re.sub(pattern, replacement, codeStr)

	if dump:
		fd = open("./%s/%s.casm" % (dumpdir, funcAddress), "w")
		fd.write(codeStr)
		fd.close()

	return codeStr

# --------------------------------------------------------------------------- #

def main():
	"""
		Test / DEBUG function!
	"""
	print "IDA PYTHON PLUGIN STARTED!!"
	if debug:
		print "DEBUG: %s" % sys.executable
		print "%s" % sys.path

	# create output directory
	if dump:
		if not os.path.exists("./%s" % dumpdir):
			os.makedirs("./%s" % dumpdir)

	# Compute Hashes and signatures for all functions
	getPerFunctionHash()

	# All done :)
	return

# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    main()

# --------------------------------------------------------------------------- #
# That's all folk ;)
# --------------------------------------------------------------------------- #