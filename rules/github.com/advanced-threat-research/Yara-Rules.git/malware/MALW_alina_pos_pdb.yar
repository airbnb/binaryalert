rule Alina_POS_PDB {

	 meta:

		 description = "Rule to detect Alina POS"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2013-08-08"
		 rule_version = "v1"
         malware_type = "pos"
         malware_family = "Pos:W32/Alina"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.pandasecurity.com/mediacenter/pandalabs/alina-pos-malware/"
		 hash = "28b0c52c0630c15adcc857d0957b3b8002a4aeda3c7ec40049014ce33c7f67c3"

	 strings:

	 	$pdb = "\\Users\\dice\\Desktop\\SRC_adobe\\src\\grab\\Release\\Alina.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 100KB and
	 	any of them
}
