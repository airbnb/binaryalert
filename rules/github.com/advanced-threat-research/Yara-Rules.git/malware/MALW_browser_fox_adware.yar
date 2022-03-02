rule malw_browser_fox_adware {
	 
	 meta:

		 description = "Rule to detect Browser Fox Adware based on the PDB reference"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2015-01-15"
		 rule_version = "v1"
         malware_type = "adware"
         malware_family = "Adware:W32/BrowserFox"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.sophos.com/en-us/threat-center/threat-analyses/adware-and-puas/Browse%20Fox.aspx"
		 hash = "c6f3d6024339940896dd18f32064c0773d51f0261ecbee8b0534fdd9a149ac64"
	 
	 strings:

	 	$pdb = "\\Utilities\\130ijkfv.o4g\\Desktop\\Desktop.OptChecker\\bin\\Release\\ BooZaka.Opt"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 800KB and
	 	any of them
}
