rule RansomWare_GermanWiper {
	meta:
		description = "Detects RansomWare GermanWiper in Memory or in unpacked state"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1158326526766657538"
		date = "2019-08-05"
		hash_packed = "41364427dee49bf544dcff61a6899b3b7e59852435e4107931e294079a42de7c"
		hash_unpacked = "708967cad421bb2396017bdd10a42e6799da27e29264f4b5fb095c0e3503e447"

	strings:
		$PurgeCode = {6a 00 8b 47 08 50 6a 00 6a 01 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b f0 8b d7 8b c3 e8} // code patterns for process kills
		$Mutex1 = "HSDFSD-HFSD-3241-91E7-ASDGSDGHH" nocase ascii
		$Mutex2 = "cFgxTERNWEVhM2V" nocase ascii
		$ProcessKill1 = "oracle.exe" nocase ascii
		$ProcessKill2 = "sqbcoreservice.exe" nocase ascii
		$ProcessKill3 = "isqlplussvc.exe"  nocase ascii
		$ProcessKill4 = "mysqld.exe" nocase ascii
		$KillShadowCopies = "vssadmin.exe delete shadows" nocase ascii
		$Domain1 = "cdnjs.cloudflare.com" nocase ascii
		$Domain2 = "expandingdelegation.top" nocase ascii
		$RansomNote = "Entschluesselungs_Anleitung.html" nocase ascii
		
	condition:
		uint16(0) == 0x5A4D and filesize < 1000KB and 5 of them
}
