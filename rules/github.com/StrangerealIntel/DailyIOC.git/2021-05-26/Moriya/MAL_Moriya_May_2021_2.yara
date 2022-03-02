rule MAL_Moriya_May_2021_2 {
   meta:
        description = "Detect Moriya rootkit used in the TunnelSnake operation"
        author = "Arkbird_SOLG"
        reference = "https://securelist.com/operation-tunnelsnake-and-moriya-rootkit/101831/"
        date = "2020-05-26"
        hash1 = "ce21319bd21f76ab0f188a514e8ab1fe6f960c257475e45a23d11125d78df428"
        tlp = "White"
        adversary = "Chinese APT Group"
   strings:
        $seq1 = { 8b 35 c4 30 40 00 8d 45 dc 68 92 24 40 00 50 ff d6 68 cc 24 40 00 8d 45 e4 50 ff d6 68 58 42 40 00 57 57 6a 22 8d 45 dc 50 57 53 ff 15 5c 30 40 00 8b f0 85 f6 0f 88 0a ff ff ff a1 58 42 40 00 83 48 1c 04 8d 45 dc 50 8d 45 e4 50 ff 15 60 30 40 00 e8 b2 00 00 00 }
        $seq2 = { 68 3c 24 40 00 50 ff 15 c4 30 40 00 8d 85 d8 fe ff ff 50 ff 15 bc 30 40 00 85 c0 74 1b 8d 8d e0 fe ff ff 51 ff d0 8b 8d e4 fe ff ff 8b 85 e8 fe ff ff 0f b7 5d f4 eb 28 53 8d 85 cc fe ff ff 50 8d 85 d4 fe ff ff 50 8d 85 d0 fe ff ff 50 ff 15 ac 30 40 00 8b 8d d0 fe ff ff 8b 85 d4 fe ff ff c1 e1 08 0f b6 c0 0b c1 0f b6 cb }
        $seq3 = { 8b 75 c0 8d 45 cc 50 ff 15 94 30 40 00 8b 5d c8 8b 43 0c 8b 55 bc 89 42 20 8b 43 08 89 42 1c 80 62 03 0f 8a 43 10 24 0f 08 42 03 8b 4b 08 85 c9 74 30 80 7e 24 00 74 06 f6 43 10 20 75 17 8b 46 18 85 c0 78 0a f6 43 10 40 75 0a 85 c0 79 20 f6 43 10 80 74 1a ff 73 0c 56 ff 75 b4 ff d1 8b f8 eb 0d 80 7e 21 00 74 07 8b 46 60 80 48 03 01 68 74 6e 68 00 53 ff 15 b4 30 40 00 }
        $seq4 = { 6a 79 68 78 6f 00 00 68 72 70 00 00 6a 69 68 73 6e 00 00 6a 5c 68 72 65 00 00 6a 76 68 69 72 00 00 68 44 5c 00 00 50 e8 a2 f8 ff ff 83 c4 30 8d 85 7c ff ff ff 50 8d 85 6c ff ff ff 50 ff 15 c4 30 40 00 a1 88 30 40 00 68 34 42 40 00 56 56 ff 30 8d 85 6c ff ff ff 56 56 6a 40 50 ff 15 90 30 40 00 }
        $seq5 = { 55 8b ec 81 ec 28 01 00 00 a1 04 40 40 00 33 c5 89 45 fc 8b 45 08 53 8b 5d 10 56 8b 75 0c 57 89 85 e8 fe ff ff 8d 7d 88 8b 45 14 6a 07 89 85 e4 fe ff ff 33 c0 59 f3 ab 33 ff 89 b5 d8 fe ff ff 68 94 00 00 00 8d 85 f0 fe ff ff 89 bd ec fe ff ff 57 50 e8 48 03 00 00 6a 06 89 7d e0 33 c0 59 8d 7d e4 f3 ab 33 ff 8d 45 a8 6a 38 57 50 89 7d a4 e8 2a 03 00 00 89 bd dc fe ff ff 8d 45 84 89 bd e0 fe ff ff 83 c4 18 89 bd dc fe ff ff 89 bd e0 fe ff ff 8d 7d 84 a5 ff b5 e4 fe ff ff 50 a5 53 a5 a5 c7 45 98 68 1b }
        $s1 = "\\Device\\MoriyaStreamWatchmen" fullword wide
        $s2 = "Moriya Filter" fullword wide
        $s3 = "Moriya Callout" fullword wide
        $s4 = "\\DosDevices\\MoriyaStreamWatchmen" fullword wide
   condition:
        uint16(0) == 0x5a4d and filesize > 6KB and (3 of ($seq*) or 2 of ($s*))
}
