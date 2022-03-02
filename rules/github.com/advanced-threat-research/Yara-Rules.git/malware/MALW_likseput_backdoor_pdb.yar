rule malw_likseput_backdoor_pdb {
	 
	 meta:
	
		 description = "Rule to detect Likseput backdoor based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2011-03-26"
		 rule_version = "v1"
         malware_type = "backdoor"
         malware_family = "Backdoor:W32/Likseput"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/bkdr_likseput.e" 
		 hash = "993b36370854587f4eef3366562f01ab87bc4f7b88a21f07b44bd5051340386d"
		 
	 strings:

	 	$pdb = "\\work\\code\\2008-7-8muma\\mywork\\winInet_winApplication2009-8-7\\mywork\\aaaaaaa\\Release\\aaaaaaa.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 40KB and
	 	any of them
}
