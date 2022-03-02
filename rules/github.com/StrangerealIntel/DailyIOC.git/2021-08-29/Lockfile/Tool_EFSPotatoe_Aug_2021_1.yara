rule Tool_EFSPotatoe_Aug_2021_1 {
   meta:
        description = "Detect custom .NET variant EFSPotatoe tool"
        author = "Arkbird_SOLG"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lockfile-ransomware-new-petitpotam-windows"
        date = "2021-08-27"
        hash1 = "c372c54b11465688201e2d48ffd5fd5b0ca49360858a70ce8413f5c9e24c8050"
        hash2 = "441cb0576151b2e5b5127be72a5bcdf3577a596f0a4e1f2c6836248fe07eb818"
        adversary = "Lockfile"
   strings:
        $s1 = { 5c 00 70 00 69 00 70 00 65 00 5c 00 6c 00 73 00 61 00 72 00 70 00 63 }
        $s2 = "ncacn_np" fullword wide
        $s3 = "WinSta0\\Default" fullword wide
        $s4 = { 11 00 72 cc 01 00 70 28 06 00 00 0a 00 dd de 02 00 00 00 de 12 07 14 fe 01 13 0f 11 0f 2d 07 07 6f 0f 00 00 0a 00 dc 00 28 10 00 00 0a 13 10 12 10 72 16 02 00 70 28 11 00 00 0a 0d 72 1a 02 00 70 09 72 2e 02 00 70 28 12 00 00 0a 13 04 11 04 19 16 1f 0a 20 00 08 00 00 20 00 08 00 00 16 7e 0d 00 00 0a 28 06 00 00 06 13 05 11 05 15 73 13 00 00 0a 28 14 00 00 0a 16 fe 01 13 0f 11 0f 2d 25 00 72 48 02 00 70 28 0e 00 00 0a 73 15 00 00 0a 6f 16 00 00 0a 28 0a 00 00 0a 28 06 00 00 0a 00 38 4a 02 00 00 16 73 17 00 00 0a 13 06 14 fe 06 04 00 00 06 73 18 00 00 0a 73 19 00 00 0a 13 07 11 07 17 6f 1a 00 00 0a 00 11 07 18 8d 01 00 00 01 13 11 11 11 16 11 05 8c 15 00 00 01 a2 11 11 17 11 06 a2 11 11 6f 1b 00 00 0a 00 14 fe 06 03 00 00 06 73 18 00 00 0a 73 19 00 00 0a 13 08 11 08 17 6f 1a 00 00 0a 00 11 08 09 6f 1b 00 00 0a 00 11 06 20 e8 03 00 00 6f 1c 00 00 0a 16 fe 01 13 0f 11 0f 3a 93 01 00 00 00 11 05 28 08 00 00 06 16 fe 01 13 0f 11 0f 3a 7c 01 00 00 00 28 08 00 00 0a 6f 0b 00 00 0a 13 09 72 7c 02 00 70 11 09 8c 15 00 00 01 28 1d 00 00 0a 28 06 00 00 0a 00 12 0a fe 15 08 00 00 02 12 0a 11 0a 28 02 00 00 2b 7d 1d 00 00 04 12 0a 7e 0d 00 00 0a 7d 1e 00 00 04 12 0a 17 7d 1f 00 00 04 12 0b 12 0c 12 0a 20 00 04 00 00 28 0b 00 00 06 26 12 0d fe 15 06 00 00 02 12 0e fe 15 07 00 00 02 12 0e 11 0e 28 03 00 00 2b 7d 0b 00 00 04 12 0e 11 0c 7d 1c 00 00 04 12 0e 11 0c 7d 1b 00 00 04 12 0e 72 9c 02 00 70 7d 0d 00 00 04 12 0e 20 01 01 00 00 7d 16 00 00 04 12 0e 16 7d 17 00 00 04 }
        $s5 = "EfsPotato <cmd>" wide
        $s6 = "\\\\.\\pipe\\" wide
   condition:
        uint16(0) == 0x5a4d and filesize > 10KB and 5 of ($s*)
}
