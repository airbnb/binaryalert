rule ixeshe_bled_malware_pdb {
	 meta:

		 description = "Rule to detect Ixeshe_bled malware based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-05-30"
		 rule_version = "v1"
      	 malware_type = "backdoor"
      	 malware_family = "Backdoor:W32/Ixeshe"
      	 actor_type = "Apt"
      	 actor_group = "Unknown"
		 reference = "https://attack.mitre.org/software/S0015/"
		 hash = "d1be51ef9a873de85fb566d157b034234377a4a1f24dfaf670e6b94b29f35482"
		 
	 strings:

	 	$pdb = "\\code\\Blade2009.6.30\\Blade2009.6.30\\EdgeEXE_20003OC\\Debug\\EdgeEXE.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and 
	    filesize < 200KB and 
	    any of them
}
