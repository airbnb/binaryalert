rule apt_aurora_pdb_samples {
	 
	meta:
	 
		 description = "Aurora APT Malware 2006-2010"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2010-01-11"
		 rule_version = "v1"
      	 malware_type = "backdoor"
      	 malware_family = "Backdoor:W32/Aurora"
      	 actor_type = "Cybercrime"
      	 actor_group = "Unknown"
		 reference = "https://en.wikipedia.org/wiki/Operation_Aurora"
		 hash = "ce7debbcf1ca3a390083fe5753f231e632017ca041dfa662ad56095a500f2364"
		 
 	strings:

		 $pdb = "\\AuroraVNC\\VedioDriver\\Release\\VedioDriver.pdb"
		 $pdb1 = "\\Aurora_Src\\AuroraVNC\\Avc\\Release\\AVC.pdb"
	 
 	condition:
 
 		uint16(0) == 0x5a4d and
 		filesize < 150KB and
 		any of them
}
