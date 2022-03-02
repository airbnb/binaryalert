rule ZLoader
{
    meta:
        id = "2JUpH4J7F9VVLnQm59k5t9"
        fingerprint = "b6cc36932d196457ad66df7815f1eb3a5e8561686d9184286a375bc78a209db0"
        version = "1.0"
        creation_date = "2020-04-01"
        first_imported = "2021-12-30"
        last_modified = "2022-02-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies ZLoader in memory or unpacked."
        category = "MALWARE"
        malware = "ZLOADER"
        malware_type = "LOADER"


    strings:
        /*
            00104bc0 89 f8           MOV        EAX,EDI
            00104bc2 8b 0d 00        MOV        ECX,dword ptr [PTR_s_#Irb4utunQPhJZjSn_0010b000] = 0010a4d0
                     b0 10 00
            00104bc8 99              CDQ
            00104bc9 f7 7d f0        IDIV       dword ptr [EBP + local_14]
            00104bcc 8b 45 08        MOV        EAX,dword ptr [EBP + param_1]
            00104bcf 0f b6 1c 11     MOVZX      EBX,byte ptr [ECX + EDX*0x1]=>s_#Irb4utunQPhJZ   = "#Irb4utunQPhJZjSn"
            00104bd3 32 1c 38        XOR        BL,byte ptr [EAX + EDI*0x1]
            00104bd6 88 1c 3e        MOV        byte ptr [ESI + EDI*0x1],BL
            00104bd9 8d 7f 01        LEA        EDI,[EDI + 0x1]
        */
        $code = { 89 f8 8b 0d ?? ?? ?? ?? 99 f7 7? ?? 8b 4? ?? 0f b6 1c ?? 32
    1c 38 88 1c 3e 8d 7f 01 74 ?? e8 ?? ?? ?? ?? 80 fb 7f 74 ?? 38 c3 7d
    ?? 80 fb 0d 77 ?? 0f b6 c3 b9 00 26 00 00 0f a3 c1 72 ?? }
        $dll = "antiemule-loader-bot32.dll" ascii wide fullword
        $s1 = "/post.php" ascii wide
        $s2 = "BOT-INFO" ascii wide
        $s3 = "Connection: close" ascii wide
        $s4 = "It's a debug version." ascii wide
        $s5 = "Proxifier is a conflict program, form-grabber and web-injects will not works. Terminate proxifier for solve this problem." ascii wide
        $s6 = "rhnbeqcuwzbsjwfsynex" ascii wide fullword

    condition:
        $code or $dll or (4 of ($s*))
}
