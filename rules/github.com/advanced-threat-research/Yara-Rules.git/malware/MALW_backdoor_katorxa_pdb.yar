rule kartoxa_malware_pdb {

	 meta:
	 
		 description = "Rule to detect Kartoxa POS based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2010-10-09"
		 rule_version = "v1"
         malware_type = "pos"
         malware_family = "Pos:W32/Kartoxa"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://securitynews.sonicwall.com/xmlpost/guatambu-new-multi-component-infostealer-drops-kartoxa-pos-malware-apr-08-2016/"
		 hash = "86dd21b8388f23371d680e2632d0855b442f0fa7e93cd009d6e762715ba2d054"
	 
	 strings:
	 
		$pdb = "\\vm\\devel\\dark\\mmon\\Release\\mmon.pdb"
		 
	condition:

		uint16(0) == 0x5a4d and
	 	filesize < 200KB and
	 	any of them
}
