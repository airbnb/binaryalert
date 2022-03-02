rule dropper_demekaf_pdb {
	 
	 meta:

		 description = "Rule to detect Demekaf dropper based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2011-03-26"
		 rule_version = "v1"
         malware_type = "dropper"
         malware_family = "Dropper:W32/Demekaf"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://v.virscan.org/Trojan-Dropper.Win32.Demekaf.html"
		 hash = "fab320fceb38ba2c5398debdc828a413a41672ce9745afc0d348a0e96c5de56e"
	 
 	 strings:

 		$pdb = "\\vc\\res\\fake1.19-jpg\\fake\\Release\\fake.pdb"

 	 condition:

	 	 uint16(0) == 0x5a4d and
		 filesize < 150KB and
		 any of them
}
