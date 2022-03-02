rule MAL_ZStealer_Nov_2021_1 {
    meta:
        description = "Detect ZStealer stealer used by Void Balaur group"
        author = "Arkbird_SOLG"
        reference ="https://documents.trendmicro.com/assets/white_papers/wp-void-balaur-tracking-a-cybermercenarys-activities.pdf"
        date = "2021-11-11"
        hash1 = "af89d85a3b579ac754850bd6e52e7516c2e63141107001463486cd01bc175052"
        hash2 = "5a2c9060f6cc1e6e0fd09b2b194631d2c7e7f024d9e2d3a9be64570e263f565f"
        tlp = "white"
        adversary = "Void Balaur"
    strings:
        $s1 = { 53 33 c0 55 68 71 d3 46 00 64 ff 30 64 89 20 a1 80 7f 7b 00 8b 10 ff 52 44 a1 84 7f 7b 00 8b 10 ff 52 44 8d 45 fc 50 68 80 d3 46 00 68 02 00 00 80 e8 e3 a3 f9 ff 85 c0 0f 85 94 01 00 00 8d 45 f8 ba 00 10 00 00 e8 86 83 f9 ff c7 45 f0 00 10 00 00 33 db e9 49 01 00 00 8d 45 f4 50 6a 00 8d 45 f8 e8 36 82 f9 ff 8d 55 e8 e8 e6 cd f9 ff 8b 4d e8 8d 45 ec ba bc d3 46 00 e8 12 80 f9 ff 8b 55 ec b9 fc d3 46 00 b8 02 00 00 80 e8 d4 d8 ff ff 84 c0 0f 84 01 01 00 00 8d 55 e4 8b 45 f4 e8 c5 c0 f9 ff 8b 55 e4 8d 45 f4 e8 6e 7d f9 ff 8b 55 f4 b8 14 d4 46 00 e8 cd 82 f9 ff 85 c0 7e 32 8d 45 e0 50 8b 55 f4 b8 14 d4 46 00 e8 b8 82 f9 ff 8b c8 83 c1 03 ba 01 00 00 00 8b 45 f4 e8 c2 81 f9 ff 8b 55 e0 a1 80 7f 7b 00 8b 08 ff 51 38 eb 0d 8b 55 f4 a1 80 7f 7b 00 8b 08 ff 51 38 8d 45 f4 50 6a 00 8d 45 f8 e8 90 81 f9 ff 8d 55 d8 e8 40 cd f9 ff 8b 4d d8 8d 45 dc ba bc d3 46 00 e8 6c 7f f9 ff 8b 55 dc b9 24 d4 46 00 b8 02 00 00 80 e8 2e d8 ff ff 84 c0 74 42 8d 45 f8 }
        $s2 = { 8b d9 88 55 fb 89 45 fc 33 c0 55 68 b3 2e 46 00 64 ff 30 64 89 20 33 d2 8b 45 fc e8 a0 11 fa ff b2 01 a1 2c 74 41 00 e8 94 11 fa ff 8b 55 fc 89 42 0c 8b 45 fc c6 40 08 00 33 c0 89 45 f4 33 d2 55 68 96 2e 46 00 64 ff 32 64 89 22 8d 45 f0 89 5d ec 8b 55 ec e8 9e 21 fa ff 8b 45 fc 83 c0 04 50 8b 45 f0 e8 b7 25 fa ff 50 e8 2d f5 ff ff 83 c4 08 85 c0 74 66 8b 45 fc 8b 40 04 85 c0 74 39 50 e8 26 f5 ff ff 59 89 45 f4 89 5d dc c6 45 e0 0b 8b 45 f4 89 45 e4 c6 45 e8 06 8d 45 dc 50 6a 01 b9 e4 2e 46 00 b2 01 a1 58 2c 46 00 e8 be a1 fa ff e8 9d 19 fa ff eb 23 89 5d d4 c6 45 d8 0b 8d 45 d4 50 6a 00 b9 10 2f 46 00 b2 01 a1 58 2c 46 00 e8 99 a1 fa ff e8 78 19 fa ff 33 c0 5a 59 59 64 89 10 68 9d 2e 46 00 83 7d f4 00 74 0a 8b 45 f4 50 e8 c4 f4 ff ff }
        $s3 = { 68 1d c7 45 00 64 ff 30 64 89 20 8b c3 e8 d8 89 fa ff 8d 45 fc ba 00 01 00 00 e8 17 90 fa ff c7 45 f8 ff 00 00 00 8d 45 f8 50 8d 45 fc e8 d0 8e fa ff 50 e8 f6 af fa ff c7 45 f4 ff 00 00 00 c7 45 f0 ff 00 00 00 8d 45 ec 50 8d 45 f0 50 8d 85 ec fd ff ff 50 8d 45 f4 50 8d 85 ec fe ff ff 50 8d 45 fc e8 9a 8e fa ff 50 6a 00 e8 d6 af fa ff 85 c0 0f 84 6d 01 00 00 8d 85 ec fe ff ff 50 e8 ba af fa ff 85 c0 0f 84 59 01 00 00 8d 85 ec fe ff ff 50 e8 7e af fa ff 8b f0 8d 85 ec fe ff ff 50 e8 80 af fa ff 0f b6 38 8b c3 ba 34 c7 45 00 e8 89 89 fa ff 80 3e 00 75 }
        $s4 = { a1 9c c2 49 00 8b 00 e8 e3 82 01 00 8b 93 88 01 00 00 8b 08 ff 51 54 8b f8 85 ff 7c 15 a1 9c c2 49 00 8b 00 e8 c6 82 01 00 8b d7 8b 08 ff 51 18 8b f0 6a 01 56 e8 e1 f2 fc ff 8b c3 e8 be 17 00 00 8a 93 84 01 00 00 e8 2f 61 00 00 33 c0 5a 59 59 }
        $s5 = { 45 72 72 6f 72 20 5b 25 64 5d 3a 20 25 73 2e 0d 22 25 73 22 3a 20 25 73 00 00 ff ff ff ff 0a 00 00 00 4e 6f 20 6d 65 73 73 61 67 65 }
    condition:
        uint16(0) == 0x5a4d and filesize > 300KB and all of them
}
