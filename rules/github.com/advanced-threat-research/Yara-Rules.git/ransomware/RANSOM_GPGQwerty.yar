rule crime_ransomware_windows_GPGQwerty

{
	meta:

		description = "Detect GPGQwerty ransomware"
		author = "McAfee Labs"
		date = "2018-03-21"
		rule_version = "v1"
	    malware_type = "ransomware"
	    malware_family = "Ransom:W32/GPGQwerty"
	    actor_type = "Cybercrime"
	    actor_group = "Unknown"	
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-takes-open-source-path-encrypts-gnu-privacy-guard/"
		
	strings:

		$a = "gpg.exe –recipient qwerty  -o"
		$b = "%s%s.%d.qwerty"
		$c = "del /Q /F /S %s$recycle.bin"
		$d = "cryz1@protonmail.com"

	condition:

		all of them
}
