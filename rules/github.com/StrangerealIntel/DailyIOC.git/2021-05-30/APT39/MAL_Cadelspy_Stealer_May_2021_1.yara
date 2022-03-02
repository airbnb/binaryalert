rule MAL_Cadelspy_Stealer_May_2021_1 {
   meta:
        description = "Detect Cadelspy stealer"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-05-30"
        hash1 = "8847a73bbd9477be60685ce8ec8333db933892f4d7b729fcef01ac76600de9ff"
        hash2 = "f3b0ad96c8529399bd7117bd67cdf0297191476d3a81a60b147960306ae5f068"
        hash3 = "88c947d0d0fddd1ea87f5b85982cf231c9c56e4f5e25fac405f608a1c28d8391"
        tlp = "White"
        adversary = "APT39"
   strings:      
        $str1 = "C:\\Windows\\SysEvent.exe" fullword wide
        $str2 = "\\sysprep\\sysprep.exe" fullword wide
        $str3 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
        $str4 = "@C:\\Windows\\systemw.dll" fullword wide
        $str5 = "systemw.dll" fullword ascii
        $str6 = "ApAshell32.dll" fullword wide
        $seq1 = { 55 8b ec 83 ec 14 a1 04 00 41 00 33 c5 89 45 fc 8d 45 f8 c7 45 f0 00 00 00 00 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 20 02 00 00 6a 20 6a 02 8d 45 f0 66 c7 45 f4 00 05 50 ff 15 08 30 40 00 85 c0 74 25 8d 45 ec 50 ff 75 f8 6a 00 ff 15 04 30 40 00 ff 75 f8 f7 d8 1b c0 21 45 ec ff 15 00 30 40 00 83 7d ec 00 75 05 e8 52 fd ff ff 56 68 2d 02 00 00 ff 15 30 30 40 00 68 1c 33 40 00 ff 15 20 30 40 00 6a 00 6a 00 6a 01 6a 00 6a 00 6a 02 68 1c 33 40 00 89 45 f8 ff 15 1c 30 40 00 6a 00 8b f0 8d 45 f8 50 68 00 ba 00 00 68 68 33 40 00 56 ff 15 6c 30 40 00 56 ff 15 74 30 40 00 6a 01 6a 00 6a 00 68 1c 33 40 00 68 4c 33 40 00 6a 00 ff 15 b0 30 40 00 8b 4d fc 33 c0 33 cd 5e e8 06 00 00 00 }
        $seq2 = { 8b 0d 10 32 40 00 0f 10 05 24 32 40 00 89 08 8b 0d 14 32 40 00 89 48 04 8b 0d 18 32 40 00 89 48 08 8b 0d 1c 32 40 00 89 48 0c 66 8b 0d 20 32 40 00 66 89 48 10 33 c9 a1 3c 32 40 00 0f 11 84 24 34 04 00 00 89 84 24 4c 04 00 00 f3 0f 7e 05 34 32 40 00 66 0f d6 84 24 44 04 00 00 0f 1f 40 00 0f b7 84 0c c8 0f 00 00 8d 49 02 66 89 84 0c 42 08 00 00 66 85 c0 75 e8 8d bc 24 44 08 00 00 83 c7 fe 66 8b 47 02 83 c7 02 66 85 c0 75 f4 b9 0a 00 00 00 be 40 32 40 00 f3 a5 b9 21 00 00 00 0f 10 05 58 33 40 00 66 a5 8d bc 24 54 0c 00 00 be 70 32 40 00 f3 a5 66 a5 0f 11 84 24 5c 0e 00 00 0f 10 05 78 ed 40 00 0f 11 84 24 6c 0e 00 00 0f 10 05 68 ed 40 00 0f 11 84 24 7c 0e 00 00 38 45 08 75 1f 8d 44 24 10 50 e8 23 fa ff ff 5f 5e 5b 8b 8c 24 c8 11 00 00 33 cc e8 1c 04 00 00 8b }
        $seq3 = { 8b 84 b5 e4 d9 ff ff 85 c0 74 66 50 6a 00 68 ff ff 1f 00 ff 15 28 30 40 00 8b f8 85 ff 74 52 8d 85 dc d9 ff ff 50 6a 04 8d 85 d0 d9 ff ff 50 57 ff 15 64 30 40 00 85 c0 74 32 68 04 01 00 00 8d 85 ec fb ff ff 50 ff b5 d0 d9 ff ff 57 ff 15 34 30 40 00 8d 85 ec fb ff ff 68 f8 32 40 00 50 ff 15 38 31 40 00 83 c4 08 85 c0 74 21 57 ff d3 33 ff 8b 85 e0 d9 ff ff 46 c1 e8 02 8b cf 3b f0 0f 82 7b ff ff ff 85 c9 0f 84 43 01 00 00 68 04 01 00 00 8d 85 e4 f9 ff ff 50 6a 00 ff 15 3c 30 40 00 85 c0 0f 84 24 01 00 00 8d 85 f4 fd ff ff 50 68 04 01 00 00 ff 15 14 30 40 00 8d 85 f4 fd ff ff 50 6a 00 68 14 33 40 00 50 ff 15 60 30 40 00 6a 00 8d 85 f4 fd ff ff 50 8d 85 e4 f9 ff ff 50 ff 15 58 30 40 00 85 c0 0f 84 df 00 00 00 6a 00 6a 00 6a 03 6a 00 6a 00 68 00 00 00 c0 8d 85 f4 fd ff ff 50 ff 15 1c 30 40 00 8b f0 83 fe ff 0f 84 b8 00 00 00 6a 00 8d 85 d8 d9 ff ff 50 68 00 10 00 00 8d 85 e4 e9 ff ff 50 56 ff 15 78 30 40 00 85 }
    condition:
      uint16(0) == 0x5a4d and filesize > 30KB and 5 of ($str*) and 2 of ($seq*)
}

