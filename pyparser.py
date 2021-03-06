#!/usr/bin/python
#
# This tool is an attempt to automate some taks related

# to malware unpacking.
#
# Most (if not all) of the tricks used in this tool 
# directly comes from an excellent course given
# by Nicolas Brulez (@nicolasbrulez)
#
# Tool developped by David DURVAUX for Autopsit
# (commercial brand of N-Labs sprl)
#
# TODO
#  - everything
#  - VirusTotal Support
#  - dynamic analysis (GDB? Valgring?)
#  - static code analysis with Radare2
#  - add argument for PEID
#  - save status / restore (config/analysis)
#  - extract fucnction without offset for comparison of samples
#  - ..
#
#
__author__ = 'David DURVAUX'
__contact__ = 'david@autopsit.org'
__version__ = '0.01'

# Imports required by this tool
import os
import sys
import json
import pefile
import peutils
import argparse
from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits, Decompose, DecomposeGenerator, DF_STOP_ON_FLOW_CONTROL

# Imports part of this tool
import static.vivframework

# --------------------------------------------------------------------------- #
# REPRESENTATION OF THE CONFIGURATION
# --------------------------------------------------------------------------- #
class Configuration:

	force = False  # force to redo all the analysis
	modstatic = None  # static analysis module
	moddynamic = None # dynamic analysis module

	# DB downloaded on
	# https://raw.githubusercontent.com/viper-framework/viper/master/data/peid/UserDB.TXT (UPX not detected)
	# https://raw.githubusercontent.com/ynadji/peid/master/userdb.txt (problems)
	# http://blog.didierstevens.com/programs/yara-rules/
	signatures = peutils.SignatureDatabase('./peid/peid-userdb-rules-with-pe-module.yara')

	def __init__(self):
		return

	def save(self, filename="./config.json"):
		config = {
			"force": self.force,
			"modstatic": self.modstatic,
			"moddynamic": self.moddynamic
		}
		try:
			# write configuration to file
			fd = open(filename, "w")
			json.dump(config, fd)
			fd.close()
			print("Configuration saved to %s" % filename)
		except Exception as e:
			print("Impossible to save configuration to %s" % filename)
			print(e)
		return

	def load(self, filename="./config.json"):
		config = {}
		try:
			# read configuration from file
			fd = open(filename, "r")
			config = json.load(fd)
			fd.close()

			# update internal state
			self.__dict__[key] = config[key]
		except Exception as e:
			print("Impossible to load configuration from %s" % filename)
			print(e)
		return

# --------------------------------------------------------------------------- #
# REPRESENTATION OF THE INFO RETRIEVED
# --------------------------------------------------------------------------- #
class BinaryInformations:
	"""
		This class will represent and hold all the information
		retrieved from the binary
	"""
	vtinfo = {}
	peheader = {}
	bininfo = {}
	settings = {}
	packed_score = 0 # current packed score
	packed_test = 0  # number of test done
	breakpoints = [] # breakoint to set for unpacking
	anti_debug = False

	def __init__(self):
		return

	def log(self):
		#TODO IMPLEMENT
		return

	def save(self, filename=sys.stdout):
		print ("NOT YET IMPLEMENTED!")
		return

# --------------------------------------------------------------------------- #
# STATIC ANALYSIS OF BINARY
# --------------------------------------------------------------------------- #
class StaticAnalysis:
	"""
		Tools to analyze statically binaries

		@TODO: define access to page_size, margin, entropy_threshold and packed_score
	"""
	# class variable
	configuration = None
	binary = None
	bininfo = None
	page_size = 0
	margin= 0
	entropy_threshold = 0
	packed_score = 0

	SFLAGS = {
		"CODE" : 0x00000020,
		"DATA" : 0x00000040,
		"EXEC" : 0x20000000,
		"READ" : 0x40000000,
		"WRIT" : 0x80000000
		# other: check https://msdn.microsoft.com/en-us/library/ms809762.aspx
	}

	def __init__(self, binary, configuration, page_size=0x1000, margin=0.1, entropy_threshold = 7.0, packed_score=0):
		"""
			binary the path to the binary to analyze
		"""
		# set parameters
		self.binary = binary
		self.page_size = page_size
		self.margin =  margin
		self.entropy_threshold = entropy_threshold
		self.packed_score = packed_score

		# instanciate internal objects
		self.pe = pefile.PE(binary)
		self.bininfo = BinaryInformations()

		# keep track of the current configuration
		self.configuration = configuration

		# initialize static analysis module (TODO - add support for others)
		self.configuration.modstatic = static.vivframework.Vivisect(self.binary, self.bininfo, self.configuration.force)

		# update BinaryInformation with current settings:
		self.bininfo.settings["peanalysis"] = {
			"binary" : self.binary,
			"page_size" : self.page_size,
			"margin" : self.margin,
			"entropy_threshold" : self.entropy_threshold,
			"packed_score" : self.packed_score
		}


	# CHECK BINARY SECTIONS
	def analyzeSections(self):
		"""
			TODO: mutliple output support, number of test

			Need to Add:
			- check section names
			- check where entry point is located (in the last section)
			- first section should be writeable
			- last section should be executable
			- ...
		"""
		# check number of sections
		if(len(self.pe.sections)) != 3:
			print "ABNOMALIE in NUMBER OF SECTIONS (%d)!!" % len(self.pe.sections)
			self.bininfo.packed_score += 1
			self.bininfo.packed_test += 1

		# check section + boundary and see if it matches
		for section in self.pe.sections:
			[name, vaddr, vsize, rsize, flags] = [section.Name, section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData, section.Characteristics]
			
			# check flags
			if( int(flags ^ (self.SFLAGS["EXEC"] | self.SFLAGS["WRIT"])) == 0 ): # check if section is executable + writeable
				print "ABNOMALIE SECTION SHOULD NOT BE WRITEABLE AND EXECUTABLE (W^X violation)!!"
				self.bininfo.packed_score += 1

			# check sections sizes (incl. page alignment)
			# the rsize need to be written in a multiple of memory page size (min 1.)
			# a margin is added (could be customized)
			if (rsize / self.page_size + 1) * self.page_size * (1 + self.margin) < vsize:
				print "ABNOMALIES with VIRTUAL SIZE ALLOCATION for SECTION: %s" % name  
				self.bininfo.packed_score += 1

			# check entropy
			if(section.get_entropy() >= self.entropy_threshold):
				print "ABNORMAL ENTROPY (%s)) for SECTION: %s" % (section.get_entropy(), name)	
				self.bininfo.packed_score += 1

			# update bininfo status
			self.bininfo.packed_test += 3 # 3 tests are done for each section

		print ("TOTAL PACKED SCORE: %s / %s" % (self.bininfo.packed_score, self.bininfo.packed_test))
		return self.bininfo


	def callPEiD(self):
		"""
			Use set of YARA rules to search for known packers

			TODO - add a check on signature presence or download or end
			     - postpone initialization of signatures DB here!!
		"""
		matches = self.configuration.signatures.match(self.pe, ep_only = True)
		if(matches is not None):
			if(len(matches) > 0):
				print "PACKER FOUND: %s" % matches[0]
		return self.bininfo


	def graphSearch(self):
		"""
			Do a graph search in the code for leaf nodes
		"""
		self.configuration.modstatic.graphSearch()


	def isAntiDebug(self):
		if self.configuration.modstatic.isAntiDebug():
			print "WARNING: ANTI-DEBUGGING TRICKS FOUND!"


	def searchVirtualAlloc(self):
		self.configuration.modstatic.searchVirtualAlloc()


	def getPerFunctionHash(self):
		self.configuration.modstatic.getPerFunctionHash()

		
	def decompile(self):
		"""
			! need to take in account offset in memory ! 
			-- CODE TO REMOVE -- DEPRECATED --
		"""
		fd = open(self.binary, "rb")

		l = DecomposeGenerator(0x100, fd.read(), Decode32Bits, DF_STOP_ON_FLOW_CONTROL)
		while(l is not None):
			# -- BEGIN TEST CODE --
			for i in l:
				#print "0x%08x (%02x) %-20s %s" % (i[0],  i[1],  i[3],  i[2])
				print "0x%08x %s" % (i.address, i)
			# -- END TEST CODE --
			l = DecomposeGenerator(0x100, fd.read(), Decode32Bits, DF_STOP_ON_FLOW_CONTROL)

		fd.close()
		return


# --------------------------------------------------------------------------- #
# MAIN SECTION OF CODE
# --------------------------------------------------------------------------- #
def start_analysis(binary, configuration):
	sa = StaticAnalysis(binary, configuration)
	sa.analyzeSections()
	sa.callPEiD()
	sa.graphSearch()
	sa.isAntiDebug()
	sa.searchVirtualAlloc()

	sa.getPerFunctionHash() #TEST
	#sa.decompile() # TEST
	return

def main():
	# Argument definition
	parser = argparse.ArgumentParser(description='Analyse binaries and try to help with deobfuscation')
	parser.add_argument('-b', '--binary', help='Binary to analyze')
	parser.add_argument('-f', '--force', help='Force a fresh analysis, no restoration of previous work', action="store_true")
	parser.add_argument('-y', '--yara', help='Path to YARA DB to use to scan binary')
	parser.add_argument('-viv', '--vivisect', help='Path to vivisect installation')

	# create a configuration holder
	configuration = Configuration()

	# Start the fun part :)
	args = parser.parse_args()

	# if force flag is defined, change behaviour
	if args.force:
		configuration.force = True

	# set YARA DB signature
	if args.yara:
		if os.path.isfile(args.yara):
			configuration.signatures = args.yara
		else:
			print "ERROR: %s not found!" % args.yara
			exit()

	# TEST - save configuration for re-use
	#configuration.save()
	configuration.load()

	# set Vivisect path and Initialize
	# currently only vivisect is supported
	# this code need to be changed if other libraries get supported later
	if args.vivisect:
		if os.path.isdir(args.vivisect):
			sys.path.append(args.vivisect)
		else:
			print "ERROR: %s not found!" % args.vivisect
			exit()

	# Check if an output directory is set
	binary = None
	if args.binary:
		if os.path.isfile(args.binary):
			binary = args.binary
			start_analysis(binary, configuration)
	else:
		print "You need to specify a file to analyze"
		exit()

if __name__ == "__main__":
    main()

# --------------------------------------------------------------------------- #
# That's all folk ;)
# --------------------------------------------------------------------------- #