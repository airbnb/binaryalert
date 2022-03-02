rule chikdos_malware_pdb
{
	 meta:

		 description = "Chikdos PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2013-12-02"
		 rule_version = "v1"
         malware_type = "dos"
         malware_family = "Dos:W32/ChickDos"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "http://hackermedicine.com/tag/trojan-chickdos/"
		 hash = "c2a0e9f8e880ac22098d550a74940b1d81bc9fda06cebcf67f74782e55e9d9cc"
	 
	 strings:

	 	$pdb = "\\IntergrateCHK\\Release\\IntergrateCHK.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 600KB and
	 	any of them
}
