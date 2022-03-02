rule MAL_NativeZone_May_2021_1 {
   meta:
        description = "Detect NativeZone malware"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-05-28"
        hash1 = "136f4083b67bc8dc999eb15bb83042aeb01791fc0b20b5683af6b4ddcf0bbc7d"
        hash2 = "3b94cc71c325f9068105b9e7d5c9667b1de2bde85b7abc5b29ff649fd54715c4"
        tlp = "White"
        adversary = "NOBELIUM"
   strings:      
        $s1 = { 8b ff 55 8b ec 81 ec 1c 01 00 00 a1 00 ?? 01 10 33 c5 89 45 fc 8b 4d 0c 53 8b 5d 14 56 8b 75 08 89 b5 fc fe ff ff 89 9d f8 fe ff ff 57 8b 7d 10 89 bd 00 ff ff ff 85 f6 75 25 85 c9 74 21 e8 [2] ff ff c7 00 16 00 00 00 e8 [2] ff ff 8b 4d fc 5f 5e 33 cd 5b e8 [2] ff ff 8b e5 5d c3 85 ff 74 db 85 db 74 d7 c7 85 f4 fe ff ff 00 00 00 00 83 f9 02 72 d8 49 0f af cf 03 ce 89 8d 04 ff ff ff 8b c1 33 d2 2b c6 f7 f7 8d 78 01 83 ff 08 0f 87 dc 00 00 00 8b bd 00 ff ff ff 3b ce 0f 86 a1 00 00 00 8d 14 37 89 95 ec fe ff ff 8d 49 00 8b c6 8b f2 89 85 08 ff ff ff 3b f1 77 31 8b ff 50 56 8b cb ff 15 [2] ?? 10 ff d3 83 c4 08 85 c0 7e 0a 8b c6 89 85 08 ff ff ff eb 06 8b 85 08 ff ff ff 8b 8d 04 ff ff ff 03 f7 3b f1 76 d1 8b d1 3b c1 74 34 2b c1 8b df 89 85 08 ff ff ff 90 8a 0c 10 8d 52 01 8b b5 08 ff ff ff 8a 42 ff 88 44 16 ff 8b c6 88 4a ff 83 eb 01 75 e3 8b 9d f8 fe ff ff 8b 8d 04 ff ff ff 8b b5 fc fe ff ff 2b cf 8b 95 ec fe ff ff 89 8d 04 ff ff ff 3b }
        $s2 = { 8b b5 00 ff ff ff 8b cb 8b 85 fc fe ff ff d1 ef 0f af fe 03 f8 57 50 ff 15 [3] 10 ff d3 83 c4 08 85 c0 7e 10 56 57 ff b5 fc fe ff ff e8 1b fe ff ff 83 c4 0c ff b5 04 ff ff ff 8b cb ff b5 fc fe ff ff ff 15 [3] 10 ff d3 83 c4 08 85 c0 7e 15 56 ff b5 04 ff ff ff ff b5 fc fe ff ff e8 e9 fd ff ff 83 c4 0c ff b5 04 ff ff ff 8b cb 57 ff 15 [3] 10 ff d3 83 c4 08 85 c0 7e 10 56 ff b5 04 ff ff ff 57 e8 c1 fd ff ff 83 c4 0c 8b 85 04 ff ff ff 8b d8 8b b5 fc fe ff ff 8b 95 00 ff ff ff 89 85 08 ff ff ff 8d 64 24 00 3b fe 76 37 03 f2 89 b5 f0 fe ff ff 3b f7 73 25 8b 8d f8 fe ff ff 57 56 ff 15 [3] 10 ff 95 f8 fe ff ff 8b 95 00 ff ff ff 83 c4 08 85 c0 7e d3 3b fe 77 3d 8b 85 04 ff ff ff 8b 9d f8 fe ff ff 03 f2 3b f0 77 1f 57 56 8b cb ff 15 [3] 10 ff d3 8b 95 00 ff ff ff 83 c4 08 85 c0 8b 85 04 ff ff ff 7e db 8b 9d 08 ff ff ff 89 b5 f0 fe ff ff 8b b5 f8 fe ff ff eb 06 8d 9b 00 00 00 00 8b 95 00 ff ff ff 8b c3 2b da 89 85 08 ff ff ff 3b df 76 1f 57 53 8b ce ff 15 [3] 10 ff d6 83 c4 08 85 c0 7f d9 8b 95 00 ff ff ff 8b 85 08 ff ff ff 8b b5 f0 fe ff ff 89 9d 08 ff ff ff }
        $s3 = { 8b 45 f4 89 7d f8 8d 04 86 8b c8 89 45 e8 8b c7 89 4d f4 3b 45 dc 74 5b 8b d6 2b d7 89 55 e4 8b 00 8b d0 89 45 ec 8d 42 01 89 45 f0 8a 02 42 84 c0 75 f9 2b 55 f0 8d 42 01 50 ff 75 ec 89 45 f0 8b 45 e8 2b c1 03 45 fc 50 51 e8 [2] 00 00 83 c4 10 85 c0 75 72 8b 45 f8 8b 55 e4 8b 4d f4 89 0c 02 83 c0 04 03 4d f0 89 4d f4 89 45 f8 3b 45 dc 75 ac 8b 45 0c 89 5d f8 89 30 8b f3 53 e8 [2] ff ff 59 8b 45 dc 8b d7 2b c2 89 55 e4 83 c0 03 c1 e8 02 39 55 dc 1b c9 f7 d1 23 c8 89 4d e8 74 18 8b f1 ff 37 e8 [2] ff ff 43 8d 7f 04 59 3b }
   condition:
        uint16(0) == 0x5a4d and filesize > 50KB and all of ($s*)
}
