rule MAL_Emotet_Nov_2021_1 {
    meta:
        description = "Detect Emotet loader"
        author = "Arkbird_SOLG"
        reference ="https://cyber.wtf/2021/11/15/guess-whos-back/"
        date = "2021-11-15"
        hash1 = "0865bd192e226da2c40b8bdd33a65ef41ca255a0031b3b36ab6a657ba6675d5e"
        hash2 = "14613fa0b6eea4cd9205ffbe1c462178c94298707d19f78a27eec3dece8765f0"
        tlp = "white"
        adversary = "TrickBot Gang"
    strings:
        $s1 = { 8b 4d 08 0f b6 02 0f b6 31 2b f0 75 18 0f b6 71 01 0f b6 42 01 2b f0 75 0c 0f b6 71 02 0f b6 42 02 2b f0 74 10 33 c9 85 f6 0f 9f c1 8d 0c 4d ff ff ff ff eb 1a 0f b6 49 03 0f b6 42 03 2b c8 74 0e 33 c0 85 c9 0f 9f c0 8d 0c 45 ff ff ff ff 8b c1 eb 56 8b 4d 08 8b 75 0c 0f b6 11 0f b6 06 2b d0 75 0c 0f b6 51 01 0f b6 46 01 2b d0 74 06 33 c9 85 d2 eb b4 0f b6 49 02 0f b6 46 02 eb be 8b 4d 08 8b 75 0c 0f b6 11 0f b6 06 2b d0 75 e0 0f b6 49 01 0f b6 46 01 eb a4 8b 45 08 0f b6 08 8b 45 0c 0f b6 00 eb 96 33 c0 5e 5b 5d c3 8b ff }
        $s2 = { 8b 75 10 83 e0 3f 8b 5d 18 6b c8 38 c1 fa 06 89 75 a0 89 5d c4 89 55 b0 8b 04 95 [2] 03 10 89 4d bc 8b 44 08 18 89 45 9c 8b 45 14 03 c6 89 45 ac ff 15 ?? 40 03 10 80 7b 14 00 89 45 90 75 07 8b cb e8 [2] ff ff 8b 43 0c 8b 75 08 8b fe 8b 40 08 89 45 98 33 c0 ab ab ab 8b 45 a0 8b d0 89 55 d0 3b 45 ac 0f 83 14 03 00 00 8b 7d bc 33 db 89 5d b8 81 7d 98 e9 fd 00 00 8a 02 88 45 cf 8b 45 b0 89 5d c0 c7 45 d4 01 00 00 00 8b 0c 85 }
        $s3 = { 53 53 40 6a 05 89 45 d0 8d 45 d8 50 ff 75 d4 8d 45 c0 50 53 ff 75 90 e8 [2] ff ff 83 c4 20 89 45 c8 85 c0 0f 84 00 01 00 00 53 8d 4d a4 51 50 8d 45 d8 50 ff 75 9c ff 15 ?? 40 03 10 85 c0 0f 84 dd 00 00 00 8b 55 d0 8b ca 2b 4d a0 8b 46 08 03 c1 89 45 b8 89 46 04 8b 45 c8 39 45 a4 0f 82 c6 00 00 00 80 7d cf 0a 75 3c 6a 0d 58 53 66 89 45 a8 8d 45 a4 50 6a 01 8d 45 a8 50 ff 75 9c ff 15 ?? 40 03 10 85 c0 0f 84 95 00 00 00 83 7d a4 01 0f 82 93 00 00 00 ff 46 08 ff 46 04 8b 46 04 8b 55 d0 89 45 b8 3b 55 ac 0f 82 6f fd ff ff eb 79 85 }
        $s4 = { ba 08 00 00 00 c1 e2 00 8b 45 f0 8b 4c 10 78 03 4d fc 89 4d f8 ba 08 00 00 00 6b c2 0c 8b 4d f0 83 7c 01 78 00 74 09 c7 45 e8 0c 00 00 00 eb 07 c7 45 e8 01 00 00 00 8b 55 e8 89 55 e4 8b 45 e4 8b 4d f0 8b 54 c1 78 89 55 dc 8b 45 e4 8b 4d f0 8b 54 c1 7c 89 55 d8 8b 45 dc 03 45 fc 89 45 d4 8d 4d c8 51 6a 04 8b 55 d8 52 8b 45 d4 50 ff 15 04 40 03 10 8b 4d f8 83 79 0c 00 0f 84 cf }
        $s5 = { 83 20 00 33 c9 21 4d e8 53 8b 5d 08 57 33 ff 89 4d e4 89 7d e0 8b 03 85 c0 74 56 8d 4d fc 66 c7 45 fc 2a 3f 51 50 c6 45 fe 00 e8 12 55 00 00 59 59 85 c0 75 1a 8d 45 e0 50 33 c0 50 50 ff 33 e8 13 01 00 00 8b f0 83 c4 10 85 f6 75 74 eb 13 8d 4d e0 51 50 ff 33 e8 ad 01 00 00 83 c4 0c 85 c0 75 1d 83 c3 04 8b 03 }
    condition:
        uint16(0) == 0x5a4d and filesize > 30KB and 4 of them
}
