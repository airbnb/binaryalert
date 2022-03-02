rule MAL_Kernel_Driver_Aug_2021_1 {
   meta:
        description = "Detect kernel driver used by lockfile group"
        author = "Arkbird_SOLG"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lockfile-ransomware-new-petitpotam-windows"
        date = "2021-08-28"
        hash1 = "5a08ecb2fad5d5c701b4ec42bd0fab7b7b4616673b2d8fbd76557203c5340a0f"
        hash2 = "0d18c704049700efd1353055b604072d94bcc3e5f4aa558adf8b8f8848330644"
        hash3 = "2b7ffe47b3fabf81a76386ee953d281aeaa158f4926896fcc1425c3844e73597"
        hash4 = "61423a95146d5fca47859e43d037944edb32f2004d86e14c7a522270bde6e2a8f"
        adversary = "Lockfile"
   strings:
        $s1 = "\\BaseNamedObjects\\{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}" fullword wide
        $s2 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%ws" fullword wide
        $s3 = "\\DosDevices\\%wS" fullword wide
        $s4 = "%temp%\\" fullword wide
        $s5 = { 5b 2b 5d 20 50 72 6f 63 65 73 73 20 6f 62 6a 65 63 74 20 28 45 50 52 4f 43 45 53 53 29 20 66 6f 75 6e 64 2c 20 30 78 25 6c 6c 58 0d 0a 00 00 00 5b 2b 5d 20 45 50 52 4f 43 45 53 53 2d 3e 50 53 5f 50 52 4f 54 45 43 54 49 4f 4e 2c 20 30 78 25 6c 6c 58 }
        $s6 = { 48 8b 4e 20 41 b9 00 08 00 00 4d 8b c7 49 8b d5 41 ff 54 24 70 85 c0 75 09 48 8d 15 [2] 02 00 eb 49 48 8d 0d [2] 02 00 e8 b9 ef ff ff 48 8d 0d [2] 02 00 e8 ad ef ff ff 4c 8d 85 f0 02 00 00 ba 00 00 00 c0 48 8d 0d [2] 02 00 e8 [2] 00 00 ba d0 07 00 00 49 8b ce ff 15 [2] 01 00 85 c0 74 15 48 8d 15 [2] 02 00 b9 01 00 00 00 e8 [2] 00 00 33 db eb 0b 48 8b d7 48 8b ce e8 4b f3 ff ff 49 8b ce ff 15 }
   condition:
        uint16(0) == 0x5a4d and filesize > 10KB and all of ($s*)
}
