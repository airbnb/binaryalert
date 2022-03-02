rule apt_mirage_pdb {
		 
	meta:
	
		 description = "Rule to detect Mirage samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-09-18"
		 rule_version = "v1"
         malware_type = "trojan"
         malware_family = "Trojan:W32/Mirage"
         actor_type = "Apt"
         actor_group = "Unknown"
		 reference = "https://www.secureworks.com/research/the-mirage-campaign"
		 hash = "0107a12f05bea4040a467dd5bc5bd130fd8a4206a09135d452875da89f121019"
		 
	strings:

		 $pdb = "\\MF-v1.2\\Server\\Debug\\Server.pdb"
		 $pdb1 = "\\fox_1.2 20110307\\MF-v1.2\\Server\\Release\\MirageFox_Server.pdb"

	condition:

		uint16(0) == 0x5a4d and
 		filesize < 150KB and
 		any of them
}
