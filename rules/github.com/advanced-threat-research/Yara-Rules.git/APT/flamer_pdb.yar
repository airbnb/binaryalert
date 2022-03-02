rule apt_flamer_pdb
{
	 meta:

		 description = "Rule to detect Flamer based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-05-29"
		 rule_version = "v1"
      	 malware_type = "backdoor"
      	 malware_family = "Backdoor:W32/Flamer"
      	 actor_type = "Apt"
     	 actor_group = "Unknown"
		 reference = "https://www.forcepoint.com/ko/blog/x-labs/flameflamerskywiper-one-most-advanced-malware-found-yet"
		 hash = "554924ebdde8e68cb8d367b8e9a016c5908640954ec9fb936ece07ac4c5e1b75"
		 
	 strings:

	 	$pdb = "\\Projects\\Jimmy\\jimmydll_v2.0\\JimmyForClan\\Jimmy\\bin\\srelease\\jimmydll\\indsvc32.pdb"

	 condition:

		uint16(0) == 0x5a4d and 
	    filesize < 500KB and 
	    any of them
}
