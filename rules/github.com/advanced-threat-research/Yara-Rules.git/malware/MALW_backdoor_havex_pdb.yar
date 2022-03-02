rule havex_backdoor_pdb {
	 
	 meta:

		 description = "Rule to detect backdoor Havex based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-11-17"
		 rule_version = "v1"
         malware_type = "backdoor"
         malware_family = "Backdoor:W32/Havex"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.f-secure.com/v-descs/backdoor_w32_havex.shtml"
		 hash = "0f4046be5de15727e8ac786e54ad7230807d26ef86c3e8c0e997ea76ab3de255"
		 
 	strings:

		 $pdb = "\\Workspace\\PhalangX 3D\\Src\\Build\\Release\\Phalanx-3d.ServerAgent.pdb"
		 $pdb1 = "\\Workspace\\PhalangX 3D\\Src\\Build\\Release\\Tmprovider.pdb"

	condition:

 		uint16(0) == 0x5a4d and
	 	filesize < 500KB and
	 	any of them
}
