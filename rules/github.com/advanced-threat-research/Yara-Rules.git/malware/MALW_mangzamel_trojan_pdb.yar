rule malw_mangzamel_trojan
{
	 meta:

		 description = "Rule to detect Mangzamel  trojan based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2014-06-25"
		 rule_version = "v1"
         malware_type = "trojan"
         malware_family = "Trojan:W32/Mangzamel"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mangzamel"
		 hash = "4324580ea162a636b7db1efb3a3ba38ce772b7168b4eb3a149df880a47bd72b7"
		 
	 strings:

		 $pdb = "\\svn\\sys\\binary\\i386\\agony.pdb"
		 $pdb1 = "\\Windows\\i386\\ndisdrv.pdb"

	condition:
		
		uint16(0) == 0x5a4d and
	 	filesize < 360KB and
	 	any of them
}
