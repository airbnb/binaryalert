rule apt_gauss_pdb {
	 
	 meta:

		 description = "Rule to detect Gauss based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-08-14"
		 rule_version = "v1"
      	 malware_type = "backdoor"
      	 malware_family = "Backdoor:W32/Gauss"
      	 actor_type = "Apt"
      	 actor_group = "Unknown"
		 reference = "https://securelist.com/the-mystery-of-the-encrypted-gauss-payload-5/33561/"
		 hash = "7b0d0612b4ecc889a901115c2e77776ef0ea65c056b283d12e80f863062cea28"

	 strings:

		 $pdb = "\\projects\\gauss\\bin\\release\\winshell.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
 		filesize < 550KB and
 		any of them
}
