rule downloader_darkmegi_pdb {

	 meta:

		 description = "Rule to detect DarkMegi downloader based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2013-03-06"
		 rule_version = "v1"
         malware_type = "downloader"
         malware_family = "Downloader:W32/DarkMegi"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkmegi" 
		 hash = "bf849b1e8f170142176d2a3b4f0f34b40c16d0870833569824809b5c65b99fc1"

 	strings:

 		$pdb = "\\RKTDOW~1\\RKTDRI~1\\RKTDRI~1\\objchk\\i386\\RktDriver.pdb"

 	condition:

 		uint16(0) == 0x5a4d and
	 	filesize > 20000KB and
	 	any of them
}
