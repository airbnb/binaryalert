rule snake_ransomware {
	
	meta:

		description = "Rule to detect Snake ransomware"
		author = "McAfee ATR Team"
		date = "2020-02-20"
		rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/EKANS"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
		reference = "https://dragos.com/blog/industry-news/ekans-ransomware-and-ics-operations/"
		hash = "e5262db186c97bbe533f0a674b08ecdafa3798ea7bc17c705df526419c168b60"
		
	strings:

		$snake = { 43 3A 2F 55 73 ?? 72 ?? 2F 57 49 4E 31 2F 67 6F 2F 73 ?? 63 2F 6A 6F 62 6E 68 62 67 6E 6E 69 66 70 6F 64 68 68 70 ?? 6D 66 2F 6E 66 64 6C 68 6F 70 68 6B 65 69 6A 61 64 67 66 64 64 69 6D 2F 6E 66 64 6C 68 6F 70 68 6B 65 69 6A 61 64 67 66 64 64 69 6D 2F 76 74 5F 73 74 ?? 69 6E 67 2E 67 6F 00 }
	
	condition:

		 ( uint16(0) == 0x5a4d and
		 filesize < 11000KB ) and
		 all of them
	
}
