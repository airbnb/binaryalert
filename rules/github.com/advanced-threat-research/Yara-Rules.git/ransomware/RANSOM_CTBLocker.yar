rule BackdoorFCKG: CTB_Locker_Ransomware
{

	meta:

		description = "CTB_Locker"
		author = "ISG"
		date = "2015-01-20"
		rule_version = "v1"
	    malware_type = "ransomware"
	    malware_family = "Ransom:W32/CTBLocker"
	    actor_type = "Cybercrime"
	    actor_group = "Unknown"
	    reference = "https://blogs.mcafee.com/mcafee-labs/rise-backdoor-fckq-ctb-locker"
	
	strings:

		$string0 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		$stringl = "RNDBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 
		$string2 = "keme132.DLL" 
		$string3 = "klospad.pdb" 

	condition:

		3 of them 
}