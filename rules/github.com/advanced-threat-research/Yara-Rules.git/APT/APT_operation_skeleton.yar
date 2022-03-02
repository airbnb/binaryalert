rule chimera_recordedtv_modified {
	
	meta:
		
		description = "Rule to detect the modified version of RecordedTV.ms found in the Operation Skeleton"
		author = "Marc Rivero | McAfee ATR Team"
		date = "2020-04-21"
		rule_version = "v1"
        malware_type = "trojan"
        malware_family = "Trojan:W32/RecordedTV"
      	actor_type = "Apt"
      	actor_group = "Unknown"
		reference = "https://cycraft.com/download/%5BTLP-White%5D20200415%20Chimera_V4.1.pdf"
		reference = "https://medium.com/@cycraft_corp/taiwan-high-tech-ecosystem-targeted-by-foreign-apt-group-5473d2ad8730"
		hash = "66f13964c87fc6fe093a9d8cc0de0bf2b3bdaea9564210283fdb97a1dde9893b"
	
	
	strings:
		
		// Modified byte
		$byte = { C0 0E 5B C3 }
		$s1 = "Encrypted file:  CRC failed in %s (password incorrect ?)" fullword wide
    		$s2 = "EBorland C++ - Copyright 1999 Inprise Corporation" fullword ascii
   		$s3 = " MacOS file type:  %c%c%c%c  ; " fullword wide
		$s4 = "rar.lng" fullword ascii

	condition:
		
		uint16(0) == 0x5a4d and
		filesize < 900KB and
		all of them
	
}
