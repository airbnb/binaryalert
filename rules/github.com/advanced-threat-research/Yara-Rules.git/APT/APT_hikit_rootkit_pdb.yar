rule apt_hikit_rootkit {
	 
	 meta:

		 description = "Rule to detect the rootkit hikit based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2012-08-20"
		 rule_version = "v1"
      	 malware_type = "rootkit"
      	 malware_family = "Rootkit:W32/Hikit"
      	 actor_type = "Cybercrime"
      	 actor_group = "Unknown"
		 reference = "https://www.fireeye.com/blog/threat-research/2012/08/hikit-rootkit-advanced-persistent-attack-techniques-part-1.html"
		 
		 
	 strings:

		 $pdb = "\\JmVodServer\\hikit\\bin32\\RServer.pdb"
		 $pdb1 = "\\JmVodServer\\hikit\\bin32\\w7fw.pdb"
		 $pdb2 = "\\JmVodServer\\hikit\\bin32\\w7fw_2k.pdb"
		 $pdb3 = "\\JmVodServer\\hikit\\bin64\\w7fw_x64.pdb"

	 condition:

	      uint16(0) == 0x5a4d and 
	      filesize < 100KB and 
	      any of them
}
