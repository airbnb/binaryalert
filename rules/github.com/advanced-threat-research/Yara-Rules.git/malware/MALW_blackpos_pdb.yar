rule MALWARE_blackPOS_pdb {
	 
	 meta:

		 description = "BlackPOS PDB"
		 author = "Marc Rivero | McAfee ATR Team"
         date = "2014-01-24"         
         rule_version = "v1"
         malware_type = "pos"
         malware_family = "Pos:W32/BlackPos"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://en.wikipedia.org/wiki/BlackPOS_Malware"
		 hash = "5a963e8aca62f3cf5872c6bff02d6dee0399728554c6ac3f5cb312b2ba7d7dbf"

	 strings:

	 	 $pdb = "\\Projects\\Rescator\\MmonNew\\Debug\\mmon.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 300KB and
	 	any of them
}
