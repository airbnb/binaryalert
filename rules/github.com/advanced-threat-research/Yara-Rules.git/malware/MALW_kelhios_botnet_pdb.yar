rule kelihos_botnet_pdb {
	 
	 meta:
	
		 description = "Rule to detect Kelihos malware based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2013-09-04"
		 rule_version = "v1"
         malware_type = "botnet"
         malware_family = "Botnet:W32/Kelihos"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.malwaretech.com/2017/04/the-kelihos-botnet.html"
		 hash = "f0a6d09b5f6dbe93a4cf02e120a846073da2afb09604b7c9c12b2e162dfe7090"
		 
	 strings:

		 $pdb = "\\Only\\Must\\Not\\And.pdb"
		 $pdb1 = "\\To\\Access\\Do.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 1440KB and
	 	any of them
}
