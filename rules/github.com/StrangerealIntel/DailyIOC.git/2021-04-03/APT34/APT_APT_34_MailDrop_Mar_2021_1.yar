rule APT_APT_34_MailDrop_Mar_2021_1 {
   meta:
        description = "Detect MailDrop malware used by APT34"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-04-03"
        hash1 = "d6b876d72dba94fc0bacbe1cb45aba493e4b71572a7713a1a0ae844609a72504"
        hash2 = "ebae23be2e24139245cc32ceda4b05c77ba393442482109cc69a6cecc6ad1393"
   strings:
        $EWSInitCom = { 7e ?? 00 00 04 28 ?? 00 00 06 ?? 4f [0-3] 02 7b ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 02 7b ?? 00 00 04 6f ?? 00 00 06 02 7b ?? 00 00 04 28 ?? 00 00 06 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 02 7b ?? 00 00 04 6f ?? 00 00 06 7e ?? 00 00 04 72 ?? 00 00 70 28 ?? 00 00 06 7e 06 00 00 04 28 ?? 00 00 06 [2-4] 00 00 [3-4] 00 00 [3] 00 00 [3] 00 00 [3] 00 00 }
        $EWSCom = { 13 30 ?? 00 ?? 00 00 00 00 00 00 00 02 28 ?? 00 00 ?? 02 03 05 0e 04 0e 05 0e 06 [0-4] 73 ?? 00 00 06 7d ?? 00 00 04 04 [2-6] 00 00 ?? 02 ?? 7d ?? 00 00 04 [0-2] 02 ?? 7d ?? 00 00 04 [2-4] 00 00 [0-18] 04 02 28 ?? 00 00 06 2a }
        $EWSDecrypt = { 13 30 03 00 27 00 00 00 ?? 00 00 11 0f 00 20 00 01 00 00 16 28 ?? 00 00 06 28 ?? 00 00 06 0a 0f 00 1f 10 16 28 ?? 00 00 06 0b 02 06 07 28 ?? 00 00 06 2a }
        $EWSRandomData = { 1b 30 ?? 00 ?? 00 00 00 ?? 00 00 11 02 19 28 ?? 00 00 0a 0a 16 0b ?? 35 [0-3] 06 16 6a 16 6f ?? 00 00 0a 26 06 6f ?? 00 00 0a d4 8d ?? 00 00 01 0c 7e ?? 00 00 04 08 6f ?? 00 00 0a 06 08 16 06 6f ?? 00 00 0a b7 6f ?? 00 00 0a 07 17 d6 0b 07 1f 32 32 c6 [5-11] 06 6f ?? 00 00 0a dc 2a [0-1] 01 10 00 00 02 00 08 00 }
        $s1 = "HMicrosoft Office/15.0 (Windows NT {0}; Microsoft Outlook 15.0.4675; Pro)" fullword ascii
        $s2 = "https://{0}/ews/exchange.asmx" fullword wide
        $s3 = "Send_Log" fullword ascii
        $s4 = "CheckEWSConnection" fullword ascii
        $s5 = "Done:D" fullword wide
        $s6 = "ExecAllCmds" fullword ascii
        $s7 = "ExchangeUri" fullword ascii
        $s8 = "get_cmdSubject" fullword ascii
   condition:
        uint16(0) == 0x5a4d and filesize > 20KB and 2 of ($EWS*) and 5 of ($s*)
}

