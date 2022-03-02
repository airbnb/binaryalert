rule MAL_loader_Lockfile_Aug_2021_1 {
   meta:
        description = "Detect loader used by lockerfile group"
        author = "Arkbird_SOLG"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lockfile-ransomware-new-petitpotam-windows"
        date = "2021-08-28"
        hash1 = "ed834722111782b2931e36cfa51b38852c813e3d7a4d16717f59c1d037b62291"
        adversary = "Lockfile"
   strings:
        $s1 = "c:\\windows\\system32\\calc.exe" fullword ascii 
        $s2 = { 49 48 85 c0 7f ec eb 0a 33 c9 66 89 0c 45 [2] 01 10 68 [2] 00 10 68 [2] 01 10 ff 15 [2] 00 10 6a 00 68 80 00 00 00 6a 03 6a 00 6a 02 68 00 00 00 80 68 [2] 01 10 ff 15 [2] 00 10 83 f8 ff 75 08 6a 00 ff 15 [2] 00 10 50 ff 15 [2] 00 10 c3 cc cc cc cc cc cc cc cc cc cc cc cc cc cc }
        $s3 = "/proc/123/stat" fullword ascii
        $s4 = { 33 c5 89 45 fc a1 [2] 00 10 8b 15 [2] 00 10 8b 0d [2] 00 10 56 89 45 dc 66 a1 [2] 00 10 57 89 55 e4 89 4d e0 8a 0d [2] 00 10 66 89 45 e8 33 c0 8d 55 dc 68 [2] 00 10 52 bf [2] 00 10 88 4d ea 89 45 eb 89 45 ef 89 45 f3 89 45 f7 88 45 fb e8 [2] 00 00 8b f0 83 c4 08 85 f6 74 44 8d 64 24 00 56 e8 [2] 00 00 83 c4 04 83 f8 ff 74 29 83 f8 28 75 ed 56 e8 [2] 00 00 83 c4 04 83 f8 ff 74 16 0f be 0f 3b c1 75 0f 56 47 e8 [2] 00 00 83 c4 04 83 f8 ff 75 ea 56 e8 [2] 00 00 83 c4 04 6a 00 ff 15 }
   condition:
        uint16(0) == 0x5a4d and filesize > 10KB and 3 of ($s*)
}
