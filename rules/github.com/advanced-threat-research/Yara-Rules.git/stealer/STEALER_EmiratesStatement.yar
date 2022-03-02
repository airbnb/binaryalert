rule STEALER_emirates_statement 
{
	meta:

		description = "Credentials Stealing Attack"
		author = "Christiaan Beek | McAfee ATR Team"
		date = "2013-06-30"
		rule_version = "v1"
        malware_type = "stealer"
        malware_family = "Stealer:W32/DarkSide"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        hash = "7cf757e0943b0a6598795156c156cb90feb7d87d4a22c01044499c4e1619ac57"
	
	strings:

		$string0 = "msn.klm"
		$string1 = "wmsn.klm"
		$string2 = "bms.klm"
	
	condition:
	
		all of them
}
