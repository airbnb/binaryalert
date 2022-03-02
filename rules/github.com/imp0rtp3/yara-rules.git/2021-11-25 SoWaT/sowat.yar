import "elf"

rule apt_CN_31_sowat_strings
{
	meta:
		author      = "@imp0rtp3"
		description = "Apt31 router implant (SoWaT) strings"
		reference   = "https://imp0rtp3.wordpress.com/2021/11/25/sowat/"
		
	strings:
		$a1 = "exc_cmd time out" fullword
		$a2 = "exc_cmd pipe err" fullword
		$a3 = "./swt  del" fullword
		$a4 = "mv -f %s %s ;chmod 777 %s " fullword
		$a5 = "./%s  port  %d " fullword
		$a6 = "./%s  del  %d " fullword
		
		// Likely deleted in next versions
		$a7 = "Usage : ntpclient destination\n" fullword
		$a8 = "killedd" fullword
		
		// Chacha encryption key
		$a9 = {53 14 3d 23 94 78 a9 68 2f 68 c9 a2 1a 93 3c 5b 39 52 2d 1d e0 63 59 1c 30 44 a2 6a 2a 3f a2 95 }

		$b1 = "nameserver" fullword
		$b2 = "conf" fullword
		$b3 = "swt" fullword
		$b4 = "192.168." fullword
		$b5 = "rm %s " fullword
		$b6 = "ipecho.net" fullword
		$b7 = "Host: ipecho.net\x0d\x0a" 
		$b8 = "send errno: %d\x0a" fullword
		$b9 = "exit 0" fullword
		
		// Likely deleted in next versions
		$b10 = "ctrl-c" fullword
		$b11 = "malloc err" fullword
		
	condition:
		uint32(0) == 0x464c457f and
		filesize < 2MB and
		(
			9 of ($b*) or
			3 of ($a*) or
			( 
				6 of ($b*) and 
				any of ($a*)
			) or (
				3 of ($b*) and 
				2 of ($a*)
			)
		)
}

rule apt_CN_31_sowat_code
{
	meta:
		author      = "@imp0rtp3"
		description = "Apt31 router implant (SoWaT) unique code (relevant only for MIPS)"
		reference   = "https://imp0rtp3.wordpress.com/2021/11/25/sowat/"

	strings:
		$c1 = { 25 38 00 00 [8] 38 00 1? 9A 09 F8 20 03 2? 20 A0 02 10 40 92 8E }
		$c2 = { 06 00 30 12 25 20 00 02 04 00 70 12 00 00 00 00 09 F8 20 03 00 00 00 00 ?? 00 BC 8F 01 00 10 26 }
		$c3 = { 00 01 02 24 25 38 00 00 02 00 06 24 ?? 00 A2 A7 09 F8 20 03 ?? 00 A5 27 }
		$c4 = { 09 F8 20 03 25 20 ?0 02 0B 00 02 24 0? 00 22 12 ?? 00 BC 8F }
		$c5 = { ?5 26 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 10 00 04 24 ?? ?? ?5 26 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 0F 00 04 24 01 00 05 24 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 0D 00 04 24 ?? ?? ?5 26 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 0A 00 04 24 } 
		$c6 = { 08 00 03 3C ?? ?? 99 8F 04 00 05 24 80 00 63 24 25 20 00 0? 09 F8 20 03 25 30 43 00 ?? 00 40 04 ?? 00 BC 8F ?? ?? 99 8F 01 00 05 24 09 F8 20 03 0D 00 04 24 }
	
	condition:
		uint32(0) == 0x464c457f and 
		filesize < 2MB and
		(
			elf.machine == elf.EM_MIPS_RS3_LE or
			elf.machine == elf.EM_MIPS
		) and 4 of ($c*)

}
