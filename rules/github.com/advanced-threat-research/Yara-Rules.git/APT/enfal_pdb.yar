rule enfal_pdb
{
	 meta:

		 description = "Rule to detect Enfal malware"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2013-08-27"
		 rule_version = "v1"
      	 malware_type = "backdoor"
      	 malware_family = "Backdoor:W32/Enfal"
      	 actor_type = "Apt"
      	 actor_group = "Unknown"
		 reference = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/enfal"
		 hash = "6756808313359cbd7c50cd779f809bc9e2d83c08da90dbd80f5157936673d0bf"

	 strings:

		 $pdb = "\\Documents and Settings\\Administrator\\My Documents\\Work\\EtenFalcon\\Release\\DllServiceTrojan.pdb"
		 $pdb1 = "\\Documents and Settings\\Administrator\\My Documents\\Work\\EtenFalcon\\Release\\ServiceDll.pdb"
		 $pdb2 = "\\Release\\ServiceDll.pdb"
		 $pdb3 = "\\muma\\0511\\Release\\ServiceDll.pdb"
		 $pdb4 = "\\programs\\LuridDownLoader\\LuridDownloader for Falcon\\ServiceDll\\Release\\ServiceDll.pdb"
	 
	 condition:

	 	uint16(0) == 0x5a4d and
 		filesize < 150KB and
 		any of them
}
