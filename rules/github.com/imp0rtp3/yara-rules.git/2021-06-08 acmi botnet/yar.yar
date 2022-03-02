private rule is_executable
{
	condition:
		uint16(0) == 0x5A4D or uint32(0) == 0x464c457f or uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca
}

rule crime_ZZ_botnet_aicm
{
	meta:
		author      = "imp0rtp3"
		description = "DDoS Golang Botnet sample for linux called 'aicm'"
		reference   = "https://twitter.com/IntezerLabs/status/1401869234511175683"
		sha256      = "496a46a07ae436b82b87bef642afbb3b06d9dbf0e0fae0199f6389f312fa4e57"

	strings:
		$a1 = "51.75.68.215:420"

		// Function Names
		$f1 = "main.Connect" fullword
		$f2 = "main.AwaitCommands" fullword
		$f3 = "Methods.randomString" fullword
		$f4 = "Methods.randomDigit" fullword
		$f5 = "Methods.randomToken" fullword
		$f6 = "Methods.SimpleGet" fullword
		$f7 = "Methods.SimplePost" fullword

		$b1 = "/root/bot/Methods.userAgents\x00"
		$b2 = "/root/bot/bot.go\x00"
		$b3 = "Ping RecievedReset Content"
		$b4 = "[BOT] | Failed to connect, Retrying"
		$b5 = "HTTP FLOOD | Starting for "

		// Address 0x6409C2 in 'main.AwaitCommands'
		$opcodes_1 = {48 83 ?? 09 0F [3] 00 00 48 B? 68 74 74 70 2D [3] 48 39 ?? 0F }        
		
		//  Address 0x640CDF in 'main.AwaitCommands'
		$weak_opcodes_1 = { 48 B? 68 74 74 70 2D 70 6F 73 48 B? 68 74 74 70 2D 67 65 74 }
		$weak_opcodes_2 = { 48 B? 68 74 74 70 2D 67 65 74 48 B? 68 74 74 70 2D 70 6F 73 }


		// Appear in 'Methods.SimplePost' and 'Methods.SimpleGet'
		$constant_1 = {80 7F B1 D7 0D 00 00 00}
		$constant_2 = {00 00 1A 3D EB 03 B2 A1}
		$constant_3 = {00 09 6E 88 F1 FF FF FF}
		 
		$ua1 = "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3"
		$ua2 = "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1090.0 Safari/536.6"
		$ua3 = "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.120 Safari/535.2"
		$ua4 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6"
		$ua5= "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1"
		$ua6 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.27 (KHTML, like Gecko) Chrome/12.0.712.0 Safari/534.27"
		$ua7 = "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.15"
		$ua8 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36"
		$ua9 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
		$ua10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3191.0 Safari/537.36"
		$ua11 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2869.0 Safari/537.36"
		$ua12 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/532.5 (KHTML, like Gecko) Chrome/4.0.249.0 Safari/532.5"
		$ua13 = "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/532.9 (KHTML, like Gecko) Chrome/5.0.310.0 Safari/532.9"
		$ua14 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7"
		$ua15 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.14 (KHTML, like Gecko) Chrome/10.0.601.0 Safari/534.14"
		$ua16 = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.14) Gecko/20110218 AlexaToolbar/alxf-2.0 Firefox/3.6.14"
		$ua17 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML like Gecko) Maxthon/4.0.0.2000 Chrome/22.0.1229.79 Safari/537.1"

	condition:
		is_executable and (
			$a1 or 6 of ($f*) or 3 of ($b*) or all of ($ua*) or (
				any of ($b*) and (
					3 of ($f*) or
					$opcodes_1 or
					(for all of ($constant*): (# > 2))  or
					10 of ($ua*)
				) or
				any of ($weak_opcodes_*) and (
					(2 of ($f*) and (
						$opcodes_1 or 
						2 of ($constant*)
						)
					) or
					14 of ($ua*)
				)
			)
		)
}