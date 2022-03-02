rule malw_cutwail_pdb {

	 meta:

		 description = "Rule to detect cutwail based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2008-04-16"
		 rule_version = "v1"
         malware_type = "botnet"
         malware_family = "Botnet:W32/Cutwail"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/CUTWAIL" 
		 hash = "d702f823eefb50d9ea5b336c638f65a40c2342f8eb88278da60aa8a498c75010"

	 strings:

	 	$pdb = "\\0bulknet\\FLASH\\Release\\flashldr.pdb"
	 
	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 440KB and
	 	any of them
}
