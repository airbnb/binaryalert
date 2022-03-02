rule festi_botnet_pdb {
	 
	 meta:
	 
		 description = "Rule to detect the Festi botnet based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2013-03-04"
		 rule_version = "v1"
         malware_type = "botnet"
         malware_family = "Botnet:W32/Festi"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.welivesecurity.com/2012/05/11/king-of-spam-festi-botnet-analysis/"	 
		 hash = "e55913523f5ae67593681ecb28d0fa1accee6739fdc3d52860615e1bc70dcb99"
		 
	 strings:

	 	$pdb = "\\eclipse\\botnet\\drivers\\Bin\\i386\\kernel.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 80KB and
	 	any of them
}
