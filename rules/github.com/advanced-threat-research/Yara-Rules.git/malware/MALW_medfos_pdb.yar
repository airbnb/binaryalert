rule malw_medfos {
	 
	 meta:
	
		 description = "Rule to detect Medfos trojan based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2013-04-19"
		 rule_version = "v1"
         malware_type = "trojan"
         malware_family = "Trojan:W32/Medfos"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=win32%2Fmedfos"
		 hash = "3582e242f62598445ca297c389cae532613afccf48b16e9c1dcf1bfedaa6e14f"
		 
	 strings:

		 $pdb = "\\som\\bytguqne\\jzexsaf\\gyin.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 150KB and
	 	any of them
}
