rule Lazarus_2020
{
	meta:
		copyright = "Intezer Labs"
		author = "Intezer Labs"
		reference = "https://analyze.intezer.com"
		date = "2020-06-11"
	strings:
		$s1 = "Can't create file %s, errno = %d, nCreateRetryCount = %d" fullword wide ascii
		$s2 = "ExploreDirectory, csDirectoryPath = %s, dwError=%d" fullword wide ascii
		$s3 = "CreateProcess %s failure, errno = %d" fullword wide ascii
		$s4 = "Can't create file %s, errno = %d, nCreateRetryCount = %d" fullword wide ascii
		$s5 = "Can't create file %s, errno = %d" fullword wide ascii
		$s6 = "Can't open user32.dll, %d" fullword wide ascii
		$s7 = "Unable to GetProcAddress of GetProcAddress" fullword wide ascii
		$s8 = "Can't find address of function Id = %d, %s" fullword wide ascii
		$s9 = "Unable to GetProcAddress of VirtualProtect" fullword wide ascii
		$s10 = "Unable to GetProcAddress of GetTickCount64" fullword wide ascii
		$s11 = "Unable to GetProcAddress of GetTickCount" fullword wide ascii
		$s12 = "Unable to GetProcAddress of FreeLibrary" fullword wide ascii
		$s13 = "Receive disconnect command from trojan" fullword wide ascii
		$s14 = "Receive Uninstall command from Trojan" fullword wide ascii
		$s15 = "Receive Update command from trojan" fullword wide ascii
		$l1 = "For more information visit <http://pcre.org/>. Alternative build from <https://github.com/kiyolee/pcre-win-build/>." fullword wide ascii
		$l2 = "\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\OneNote.lnk" fullword wide ascii
		$l3 = "C:\\Windows\\System32\\rundll32.exe \"%s\", CtrlPanel %s 0 0 %s 1" fullword wide ascii
		$l4 = "H@@__SWPJEIVJxJzObRdTd]eH~FqClew~;x&a,k-x6y6!7!5$-91>N6L\"P-\\)2V*L8D'[3S0N-M/K]K_NGS=T>\\8H G" fullword wide ascii
	
	condition:
		7 of ($s*) or all of ($l*)
	
}
