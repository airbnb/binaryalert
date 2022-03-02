rule apt_lagulon_trojan_pdb {
	 
	meta:

		description = "Rule to detect trojan Lagulon based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		date = "2013-08-31"
		rule_version = "v1"
        malware_type = "trojan"
        malware_family = "Trojan:W32/lagulon"
        actor_type = "Apt"
        actor_group = "Unknown"
		reference = "https://www.cylance.com/operation-cleaver-cylance"
		hash = "e401340020688cdd0f5051b7553815eee6bc04a5a962900883f1b3676bf1de53"

 	strings:

 		$pdb = "\\proj\\wndTest\\Release\\wndTest.pdb"

 	condition:

 		uint16(0) == 0x5a4d and 
      	filesize < 50KB and 
      	any of them
}
