rule MAL_Moriya_May_2021_1 {
   meta:
        description = "Detect Moriya rootkit used in the TunnelSnake operation"
        author = "Arkbird_SOLG"
        reference = "https://securelist.com/operation-tunnelsnake-and-moriya-rootkit/101831/"
        date = "2020-05-07"
        hash1 = "3eda93de4a1e7a35c040fad914a4885d079ffc3c1362153b74e10ff9121de22b"
        hash2 = "d620f9c32adc39b0632f22ec6a0503bf906fd1357f4435463fbb4b422634a536"
        tlp = "White"
        adversary = "Chinese APT Group"
   strings:
        $seq1 = { 4c 8d 05 13 10 00 00 ff 15 95 12 00 00 48 8d 15 36 10 00 00 48 8d 4d c0 ff 15 fc 12 00 00 48 8d 15 65 10 00 00 48 8d 4d d0 ff 15 eb 12 00 00 48 8d 05 cc 23 00 00 41 b9 22 00 00 00 48 89 44 24 30 4c 8d 45 c0 c6 44 24 28 00 33 d2 83 64 24 20 00 48 8b cb ff 15 f0 11 00 00 33 d2 41 8b ce 8b f8 85 c0 79 09 4c 8d 05 6e }
        $seq2 = { 4c 8d 05 85 10 00 00 ff 15 27 12 00 00 48 8b 05 80 23 00 00 48 8d 55 c0 48 8d 4d d0 83 48 30 04 ff 15 be 11 00 00 e8 c5 01 00 00 33 d2 41 8b ce 85 c0 79 0c }
        $seq3 = { 33 db 48 8b 74 24 30 4c 8b 7c 24 38 48 8b 7c 24 40 4c 8b 64 24 48 4d 8b ec 48 8d 4c 24 58 ff 15 b7 1c 00 00 48 8b 46 10 49 89 44 24 f8 48 8b 46 08 49 89 45 f0 41 80 65 bb 0f 8a 46 18 24 0f 41 08 45 bb 4c 8b 4e 08 }
        $seq4 = { 48 83 64 24 58 00 ba 44 5c 00 00 c7 44 24 50 79 00 00 00 41 b9 76 00 00 00 c7 44 24 48 78 6f 00 00 41 b8 69 72 00 00 c7 44 24 40 72 70 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 73 6e 00 00 c7 44 24 28 5c 00 00 00 c7 44 24 20 72 65 00 00 e8 03 f6 ff ff 48 8d 55 80 48 8d 4c 24 70 ff 15 74 17 00 00 48 8d 05 2d 28 00 00 45 33 c9 48 89 44 24 38 45 33 c0 48 8b 05 eb 16 00 00 48 83 64 24 30 00 c6 44 24 28 00 41 8d 51 40 48 8b 08 48 89 4c 24 20 48 8d 4c 24 70 ff 15 d9 16 00 00 85 c0 78 31 48 8b 0d ee 27 00 00 48 8b 81 e0 00 00 00 48 89 05 d8 27 00 00 48 8d 05 19 f7 ff ff 87 81 e0 00 00 00 48 8b 0d cc 27 00 00 ff 15 c6 16 00 00 33 c0 48 8b 4d 00 48 33 cc e8 58 0b 00 00 48 81 c4 10 01 00 }
        $seq5 = { 40 55 53 56 57 41 56 48 8d ac 24 40 ff ff ff 48 81 ec c0 01 00 00 48 8b 05 47 1e 00 00 48 33 c4 48 89 85 b8 00 00 00 48 83 64 24 38 00 49 8b d8 48 83 64 24 50 00 48 8b fa 48 8b f1 33 d2 41 b8 c8 00 00 00 48 8d 4c 24 60 4d 8b f1 e8 0b 06 00 00 33 c0 48 8d 4d 30 0f 57 c0 48 89 85 b0 00 00 00 33 d2 0f 11 85 90 00 00 00 44 8d 40 58 0f 11 85 a0 00 00 00 e8 e2 05 00 00 0f 10 07 48 83 64 24 20 00 48 8d 05 72 f8 ff ff 48 89 44 24 40 48 8d 54 24 28 48 8d 05 81 fd ff ff 4d 8b c6 48 8b cb 48 89 44 24 48 f3 0f 7f 44 24 28 e8 13 05 00 00 8b d8 85 c0 0f 88 da 00 00 00 0f 10 07 48 8b 0d f7 1f 00 00 48 8d 05 30 0a 00 00 45 33 c9 48 89 45 40 f3 0f 7f 45 30 45 33 c0 48 8d 55 30 0f 10 06 48 89 45 48 f3 0f 7f 45 70 e8 22 05 00 00 8b d8 85 c0 0f 88 93 00 00 00 0f 10 06 83 65 c0 00 48 8d 05 14 0a 00 00 0f 10 0d 5d 0f 00 00 83 a5 a0 00 00 00 00 48 8d 54 24 60 48 8b 0d 9a 1f 00 00 45 33 c9 f3 0f 7f 45 a0 48 89 44 24 70 45 33 c0 0f 10 07 48 89 44 24 78 48 8d 85 90 00 00 00 48 89 45 d8 48 8d 44 24 20 f3 0f 7f 45 e4 c7 45 e0 03 50 00 00 0f 10 05 ff 0e 00 00 c7 45 d0 01 00 00 00 f3 0f 7f 8d 90 00 00 00 c7 85 a8 00 00 00 00 01 00 00 f3 0f 7f 45 b0 48 89 85 b0 00 00 00 e8 91 04 00 00 8b d8 85 c0 79 08 41 8b 0e e8 35 04 00 00 8b c3 48 8b 8d b8 00 00 00 48 33 cc e8 96 02 00 00 48 81 c4 c0 01 00 00 41 5e 5f 5e 5b }
        $s1 = "Moriya : NotifyFunction\n" fullword ascii
        $s2 = "Moriya Filter" fullword wide
        $s3 = "Moriya : DeviceControlDispatch!\n" fullword ascii
        $s4 = "Moriya : Waiting...\n" fullword ascii
        $s5 = "Moriya : WriteDispatch!\n" fullword ascii
        $s6 = { 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4d 00 6f 00 72 00 69 00 79 00 61 00 53 00 74 00 72 00 65 00 61 00 6d 00 57 00 61 00 74 00 63 00 68 00 6d 00 65 00 6e }
        $s7 = { 5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 4d 00 6f 00 72 00 69 00 79 00 61 00 53 00 74 00 72 00 65 00 61 00 6d 00 57 00 61 00 74 00 63 00 68 00 6d 00 65 00 6e }
        $s8 = "Moriya start\n" fullword ascii
   condition:
        uint16(0) == 0x5a4d and filesize > 6KB and (3 of ($seq*) or 6 of ($s*))
}
