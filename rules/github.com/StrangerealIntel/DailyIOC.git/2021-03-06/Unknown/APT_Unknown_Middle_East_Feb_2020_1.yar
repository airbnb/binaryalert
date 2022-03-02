rule APT_Unknown_Middle_East_Feb_2020_1 {
   meta:
      description = "Dectect unknown Middle East implants (retrohunt June 2020)"
      author = "Arkbird_SOLG"
      reference = "internal Research"
      date = "2021-03-05"
      hash1 = "274beb57ae19cbc5c2027e08cb2b718dea7ed1acb21bd329d5aba33231fb699d"
      hash2 = "3a4ef9b7bd7f61c75501262e8b9e31f9e9bc3a841d5de33dcdeb8aaa65e95f76"
   strings:
   //seq BITSAdmin
   $seq1 = { 55 8b ec 83 e4 f8 81 ec 08 04 00 00 a1 34 45 49 00 33 c4 89 84 24 04 04 00 00 83 ec 08 ba [2] 48 00 b9 ?? 82 48 00 68 [2] 48 00 e8 af 9f ff ff 83 c4 04 ba [2] 48 00 b9 ?? 82 48 00 68 [2] 48 00 e8 98 9f ff ff 83 c4 04 ba [2] 48 00 b9 ?? 82 48 00 68 [2] 48 00 e8 81 9f ff ff 83 c4 0c 8d 04 24 68 00 04 00 00 6a 00 50 e8 [2] 01 00 83 c4 0c 8d 04 24 [4] 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 8d 04 24 68 ?? ab 49 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 8d 04 24 68 ?? 6c 48 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 8d 04 24 68 ?? a9 49 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 8d 04 24 68 ?? 83 48 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 33 c0 66 89 84 24 fe 03 00 00 8d 04 24 68 [2] 48 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 8d 04 24 68 ?? a6 49 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 8d 04 24 68 ?? 83 48 00 68 00 02 00 00 50 e8 [2] 02 00 8d 4c 24 0c e8 6b a1 ff ff 83 c4 04 ba [2] 48 00 b9 ?? 83 48 00 68 [2] 48 00 e8 94 9e ff ff 8b 8c 24 10 04 00 00 83 c4 0c 33 cc e8 [2] 01 00 8b e5 5d }
   // seq header + handshake
   $seq2 = { 55 8b ec 6a ff 68 [2] 47 00 64 a1 00 00 00 00 50 81 ec d8 00 00 00 a1 34 45 49 00 33 c5 89 45 f0 56 57 50 8d 45 f4 64 a3 00 00 00 00 8b 45 08 8b 75 14 c7 45 fc 00 00 00 00 89 85 34 ff ff ff 89 85 40 ff ff ff 33 c0 50 50 50 50 c7 85 3c ff ff ff 00 00 00 00 68 ?? 70 48 00 89 b5 6c ff ff ff c7 85 48 ff ff ff 00 00 00 00 c7 85 44 ff ff ff 00 00 00 00 89 85 50 ff ff ff ff 15 78 55 47 00 89 85 38 ff ff ff 85 c0 74 3f 6a 00 68 bb 01 00 00 68 ?? 6d 48 00 50 ff 15 8c 55 47 00 89 85 44 ff ff ff 85 c0 74 22 68 00 00 80 00 6a 00 6a 00 6a 00 68 ?? 71 48 00 68 ?? 6d 48 00 50 ff 15 90 55 47 00 89 85 50 ff ff ff 8b 3d 44 53 47 00 6a 00 6a 00 6a 00 6a 00 6a ff 56 6a 00 68 e9 fd 00 00 ff d7 8b f0 56 e8 ?? 35 01 00 83 c4 04 89 85 4c ff ff ff 6a 00 6a 00 56 50 6a ff ff b5 6c ff ff ff 6a 00 68 e9 fd 00 00 ff d7 68 80 00 00 00 8b f8 8d 85 70 ff ff ff 6a 00 50 e8 [2] 02 00 57 8d 85 70 ff ff ff 68 ?? 79 48 00 50 e8 ?? a3 00 00 83 c4 18 c7 85 64 ff ff ff 00 00 00 00 33 c0 c7 85 68 ff ff ff 07 00 00 00 8d 8d 54 ff ff ff 66 89 85 54 ff ff ff 6a 10 68 [2] 48 00 e8 ?? 84 00 00 8d 8d 70 ff ff ff c7 45 fc 01 00 00 00 8d 51 02 66 8b 01 83 c1 02 66 85 c0 75 f5 2b ca 8d 85 70 ff ff ff d1 f9 51 50 8d 8d 54 ff ff ff e8 89 63 00 00 6a 33 68 ?? 71 48 00 8d 8d 54 ff ff ff e8 77 63 00 00 8b b5 50 ff ff ff 85 f6 }
   $s1 = "taskkill /im svehost.exe /t /f" fullword ascii
   $s2 = "\\AppData\\Windows\\svehost.exe" fullword ascii
   $s3 = "svehost.exe" fullword wide
   $s4 = "bdagent.exe" fullword wide
   $s5 = "taskkill /im keepass.exe /t /f" fullword ascii
   $s6 = "%s\\AppData\\Windows\\svehost" fullword ascii
   $s7 = "\\AppData\\Roaming\\ViberPc" fullword wide
   $s8 = "\\AppData\\Roaming\\Skype" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize > 200KB and 1 of ($seq*) and 4 of ($s*)
}
