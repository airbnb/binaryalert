rule Dridex_P2P_pdb
{
	 meta:

		 description = "Rule to detect Dridex P2P based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2014-11-29"
		 rule_version = "v1"
         malware_type = "backdoor"
         malware_family = "Backdoor:W32/Dridex"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.us-cert.gov/ncas/alerts/aa19-339a" 
		 hash = "5345a9405212f3b8ef565d5d793e407ae8db964865a85c97e096295ba3f39a78"

	 strings:

	 	$pdb = "\\c0da\\j.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 400KB and
	 	any of them
}
