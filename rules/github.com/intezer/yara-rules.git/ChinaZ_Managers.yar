private rule NewManager {
	meta:
		copyright = "Intezer Labs"
		author = "Intezer Labs"
		reference = "https://www.intezer.com"
	strings:
		$a0 = {8B ?? 04 3? 03 00 00 11 74 4D 3? 11 00 00 11 74 61 3? 02 00 00 11 } 
        $b0 = "_ConnectServer"
        $b1 = "/root/1/ampS.log"
        $b2 = "/etc/rc%d.d/S%d%s"
        $b3 = "Get SYstem Info"
        $b4 = "newmanager"
        $b5 = "NO DDXC"

	condition:
		all of them
}

private rule AmpManager {
	meta:
		copyright = "Intezer Labs"
		author = "Intezer Labs"
		reference = "https://www.intezer.com"
	strings:
		$a0 = {C7 85 ?? F8 FF FF ?? 00 00 11 C7 85 ?? F8 FF FF 00 00 00 00 C7 85 ?? F8 FF FF ?? 00 00 00} 
        $b0 = "ampserver/main.cpp"
        $b1 = "M-SEARCH * HTTP/1.1"
        $b2 = "rm -f /usr/bin/ammint | killall ammint 2>/dev/null &"
        $b3 = "ln -s /etc/init.d/%s %s"
        $b4 = "camplz123"

	condition:
		all of them
}

private rule DDoSManager { 
	meta:
		copyright = "Intezer Labs"
		author = "Intezer Labs"
		reference = "https://www.intezer.com"
	strings:
		$a0 = { 55 89 e5 5? 8b ?? 0c 8B ?? 08 85 ?? 7E 16 31 ?? 0F B6 ?? ?? 83 F? 19 83 C? 7A 88 ?? ?? 83 C? 01} 
        $b0 = "5CFake"
        $b1 = "/tmp/Cfg.9"
        $b2 = "0|%s|%s|1|65535|"
        $b3 = "8CManager"
        $b4 = "SingTool"

	condition:
		all of them
}

rule ChinaZ_Managers {
	meta:
		copyright = "Intezer Labs"
		author = "Intezer Labs"
		reference = "https://www.intezer.com"
	condition:
        NewManager or AmpManager or DDoSManager
}
