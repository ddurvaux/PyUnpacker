
#
# !! TEST FILE for raw pieces of code !!
#

__author__ = 'David DURVAUX'
__contact__ = 'david@autopsit.org'

import pefile
binfile = "./demo/36a209a7d15d5d719d6072f45e4e3b46"

# load binary
pe = pefile.PE(binfile)

# check section + boundary and see if it matches
for section in pe.sections:
	[name, vaddr, vsize, rsize] = [section.Name, section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData]
	print("%s %s %s %s" % (name, hex(vaddr), vsize, rsize))
