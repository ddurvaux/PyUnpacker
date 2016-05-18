#
# !! TEST FILE for raw pieces of code !!
#
#
# PEiD DB signatures:
#   http://handlers.sans.org/jclausing/userdb.txt
__author__ = 'David DURVAUX'
__contact__ = 'david@autopsit.org'

# IMPORTS
import pefile
import peutils
from radare import *

# SETTINGS
#binfile = "./demo/36a209a7d15d5d719d6072f45e4e3b46"
binfile = "./demo/upx.exe"
signatures = peutils.SignatureDatabase('./peid/UserDB.TXT')

# load binary
pe = pefile.PE(binfile)

# CHECK BINARY SECTIONS
def analyzeSections():

	# check section + boundary and see if it matches
	page_size = 0x1000
	margin=0.1
	entropy_threshold = 7.0
	packed_score = 0

	SFLAGS = {
		"CODE" : 0x00000020,
		"DATA" : 0x00000040,
		"EXEC" : 0x20000000,
		"READ" : 0x40000000,
		"WRIT" : 0x80000000
		# other: check https://msdn.microsoft.com/en-us/library/ms809762.aspx
	}

	for section in pe.sections:
		[name, vaddr, vsize, rsize, flags] = [section.Name, section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData, section.Characteristics]
		
		# check flags
		if( int(flags ^ (SFLAGS["EXEC"] | SFLAGS["WRIT"])) == 0 ): # check if section is executable + writeable
			print "ABNOMALIE SECTION SHOULD NOT BE WRITEABLE AND EXECUTABLE (W^X violation)!!"
			packed_score += 1

		# check sections sizes (incl. page alignment)
		# the rsize need to be written in a multiple of memory page size (min 1.)
		# a margin is added (could be customized)
		if (rsize / page_size + 1) * page_size * (1 + margin) < vsize:
			print "ABNOMALIES with VIRTUAL SIZE ALLOCATION for SECTION: %s" % name  
			packed_score += 1

		# check entropy
		if(section.get_entropy() >= entropy_threshold):
			print "ABNORMAL ENTROPY (%s)) for SECTION: %s" % (section.get_entropy(), name)	
			packed_score += 1

	print "TOTAL PACKED SCORE: %s" % packed_score
	return

def callPEiD():
	matches = signatures.match(pe, ep_only = True)
	if(len(matches) > 0):
		print "PACKER FOUND: %s" % matches[0]
	return

# GRAPH ANALYSIS
# Search leaf of graphs for JMP
def analyzeCallGraph():
	return

# MAIN
analyzeSections()
callPEiD()
analyzeCallGraph()



