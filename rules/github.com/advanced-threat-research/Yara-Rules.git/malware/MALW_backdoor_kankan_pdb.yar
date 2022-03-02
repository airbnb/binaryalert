rule backdoor_kankan_pdb {
	 
	 meta:

		 description = "Rule to detect kankan PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2013-08-01"
		 rule_version = "v1"
         malware_type = "backdoor"
         malware_family = "Backdoor:W32/Kankan"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://threatpoint.checkpoint.com/ThreatPortal/threat?threatType=malwarefamily&threatId=650"
		 hash = "73f9e28d2616ee990762ab8e0a280d513f499a5ab2cae9f8cf467701f810b98a"

 	strings:

		 $pdb = "\\Projects\\OfficeAddin\\INPEnhSvc\\Release\\INPEnhSvc.pdb"
		 $pdb1 = "\\Projects\\OfficeAddin\\OfficeAddin\\Release\\INPEn.pdb"
		 $pdb2 = "\\Projects\\OfficeAddinXJ\\VOCEnhUD\\Release\\VOCEnhUD.pdb"
 
	condition:

 		uint16(0) == 0x5a4d and
	 	filesize < 500KB and
	 	any of them
}
