rule APT_APT38_ValeforBeta_Mar_2021_1 {
   meta:
        description = "Detect ValeforBeta used in attacks against Japanese organisations by APT38"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-03-23"
        hash1 = "eb846bb491bea698b99eab80d58fd1f2530b0c1ee5588f7ea02ce0ce209ddb60"
        level = "experimental"
   strings:
        // debug outputs
        $dbg1 = { 2f 64 64 65 00 00 00 64 64 65 65 78 65 63 } //  /dde ddeexec
        $dbg2 = { 25 73 5c 53 68 65 6c 6c 4e 65 77 } // %s\\ShellNew
        $dbg3 = { 25 73 20 28 25 73 3a 25 64 29 0a 25 73 } // %s (%s:%d)\n%s
        $dbg4 = { 7b 25 30 38 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d } // {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}
        $dbg5 = { 25 73 25 73 2e 64 6c 6c } // %s%s.dll
        $dbg6 = { 25 73 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 25 73 00 00 00 00 25 73 5c 73 68 65 6c 6c 5c 70 72 69 6e 74 5c 25 73 00 00 00 25 73 5c 73 68 65 6c 6c 5c 70 72 69 6e 74 74 6f 5c 25 73 00 25 73 5c 44 65 66 61 75 6c 74 49 63 6f 6e 00 00 25 73 5c 53 68 65 6c 6c 4e 65 77 00 2c 25 64 00 63 6f 6d 6d 61 6e 64 00 20 22 25 31 22 00 00 00 20 2f 70 20 22 25 31 22 00 00 00 00 20 2f 70 74 20 22 25 31 22 20 22 25 32 22 20 22 25 33 22 20 22 25 34 22 } // ref shell commands       
        $dbg7 = { 43 4c 53 49 44 5c 25 31 5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 } //  CLSID\\%1\\InProcServer32
        $s1 = { 74 f1 ff b5 a8 fe ff ff 8d 4b 10 c7 43 08 03 00 00 00 e8 3c cf fd ff eb da 8d 8d ac fe ff ff e8 3f 1a fc ff 83 65 fc 00 8d 85 ac fe ff ff 50 57 e8 bd fd ff ff ff b5 ac fe ff ff ff 15 24 44 47 00 85 c0 0f 85 be 00 00 00 50 50 8d 8d a0 fe ff ff 51 8d 8d 9c fe ff ff 51 50 50 50 ff b5 ac fe ff ff ff 15 70 42 47 00 85 c0 75 1f ff b5 a8 fe ff ff 53 e8 dc fe ff ff 8b 8d ac fe ff ff }
        $s2 = { 45 fc 8b 45 0c 0f b6 48 0f 56 51 0f b6 48 0e 51 0f b6 48 0d 51 0f b6 48 0c 51 0f b6 48 0b 51 0f b6 48 0a 51 0f b6 48 09 51 0f b6 48 08 8b 75 08 83 a5 f8 fe ff ff 00 51 0f b7 48 06 51 0f b7 48 04 51 ff 30 8d 85 fc fe ff ff 68 48 aa 47 00 68 00 01 00 00 }
   condition:
        uint16(0) == 0x5a4d and filesize > 30KB and 5 of ($dbg*) and 1 of ($s*)
}
