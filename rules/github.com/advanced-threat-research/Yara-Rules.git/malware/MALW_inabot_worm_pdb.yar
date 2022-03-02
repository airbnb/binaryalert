rule malw_inabot_worm
{
	 meta:
		 description = "Rule to detect inabot worm based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "http://verwijderspyware.blogspot.com/2013/04/elimineren-w32inabot-worm-hoe-te.html"
		 date = "2013-04-19"
		 rule_version = "v1"
         malware_type = "worm"
         malware_family = "Worm:W32/Inabot"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 hash = "c9c010228254aae222e31c669dda639cdd30695729b8ef2b6ece06d899a496aa"
	 
	 strings:

		 $pdb = "\\trasser\\portland.pdb"
		 $pdb1 = "\\mainstream\\archive.pdb"

 condition:

 		uint16(0) == 0x5a4d and
	 	filesize < 180KB and
	 	any of them
}
