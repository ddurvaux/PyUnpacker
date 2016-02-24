#!/usr/bin/python
#
#
__author__ = 'David DURVAUX'
__contact__ = 'david@autopsit.org'

# Imports required by this tool
import argparse
import os
import pefile
import peutils

# --------------------------------------------------------------------------- #
# STATIC ANALYSIS OF BINARY
# --------------------------------------------------------------------------- #
class StaticAnalysis:
	"""
		Tools to analyze statically binaries

		@TODO: define access to page_size, margin, entropy_threshold and packed_score
	"""
	# class variables
	binary = None
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

	def __init__(self, binary):
		"""
			binary the path to the binary to analyze
		"""
		self.binary = binary
		self.pe = pefile.PE(binary)

	# CHECK BINARY SECTIONS
	def analyzeSections(self):
		"""
			TODO: mutliple output support, number of test
		"""
		# check section + boundary and see if it matches
		for section in self.pe.sections:
			[name, vaddr, vsize, rsize, flags] = [section.Name, section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData, section.Characteristics]
			
			# check flags
			if( int(flags ^ (self.SFLAGS["EXEC"] | self.SFLAGS["WRIT"])) == 0 ): # check if section is executable + writeable
				print "ABNOMALIE SECTION SHOULD NOT BE WRITEABLE AND EXECUTABLE (W^X violation)!!"
				self.packed_score += 1

			# check sections sizes (incl. page alignment)
			# the rsize need to be written in a multiple of memory page size (min 1.)
			# a margin is added (could be customized)
			if (rsize / self.page_size + 1) * self.page_size * (1 + self.margin) < vsize:
				print "ABNOMALIES with VIRTUAL SIZE ALLOCATION for SECTION: %s" % name  
				self.packed_score += 1

			# check entropy
			if(section.get_entropy() >= self.entropy_threshold):
				print "ABNORMAL ENTROPY (%s)) for SECTION: %s" % (section.get_entropy(), name)	
				self.packed_score += 1

		print "TOTAL PACKED SCORE: %s" % self.packed_score
		return


# --------------------------------------------------------------------------- #
# MAIN SECTION OF CODE
# --------------------------------------------------------------------------- #
def start_analysis(binary):
	sa = StaticAnalysis(binary)
	sa.analyzeSections()
	return

def main():
	# Argument definition
	parser = argparse.ArgumentParser(description='Analyse binaries and try to help with deobfuscation')
	parser.add_argument('-bin', '--binary', help='Binary to analyze')

	# Start the fun part :)
	args = parser.parse_args()

	# Check if an output directory is set
	binary = None
	if args.binary:
		if os.path.isfile(args.binary):
			binary = args.binary
			start_analysis(binary)
	else:
		print "You need to specify a file to analyze"

if __name__ == "__main__":
    main()

# --------------------------------------------------------------------------- #
# That's all folk ;)
# --------------------------------------------------------------------------- #