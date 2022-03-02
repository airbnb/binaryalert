rule MAL_KillProc_Aug_2021_1 {
   meta:
        description = "Detect KillProc driver used by Night Dragon for kill process before encryption"
        author = "Arkbird_SOLG"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lockfile-ransomware-new-petitpotam-windows"
        date = "2021-08-27"
        hash1 = "36e8bb8719a619b78862907fd49445750371f40945fefd55a9862465dc2930f9"
        adversary = "Lockfile"
   strings:
        $s1 = "find %s!\n" fullword ascii
        $s2 = "killed %s!\n" fullword ascii
        $s3 = "DbgPrint" fullword ascii
        $s4 = "ntoskrnl.exe" fullword ascii
        $s5 = "SBPIMSvc.exe" fullword ascii
        $s6 = "MsMpEng.exe" fullword ascii
        $s7 = { 48 8b ce ff 15 92 cf ff ff 48 8b d0 48 8b cb ff 15 8e cf ff ff 48 8d 7f 08 85 c0 74 0d 48 8b 1f 44 38 23 75 db e9 a7 00 00 00 48 8b ce ff 15 68 cf ff ff 48 8b d0 48 8d 0d 6e bf ff ff ff 15 70 cf ff ff 48 8b ce ff 15 37 cf ff ff 8b c8 48 8d 54 24 40 ff 15 3a cf ff ff 85 c0 78 56 48 8b 4c 24 40 48 8d 84 24 a8 00 00 00 48 89 44 24 30 45 33 c9 44 88 64 24 28 45 33 c0 33 d2 4c 89 64 24 20 ff 15 04 cf ff ff 85 c0 74 05 45 32 f6 eb 41 48 8b 8c 24 a8 00 00 00 33 d2 ff 15 0b cf ff ff 48 8b 8c 24 a8 00 00 00 ff 15 0d cf ff ff 41 b6 01 eb 05 45 84 f6 74 19 48 8b ce ff 15 da ce ff ff 48 8b d0 48 8d 0d f0 be ff ff ff 15 e2 ce ff ff 48 8b ce ff 15 a1 ce ff ff 48 83 }
        $s8 = "UpdaterUI.exe" fullword ascii
        $s9 = "VipreNis.exe" fullword ascii
   condition:
        uint16(0) == 0x5a4d and filesize > 3KB and 6 of ($s*)
}
