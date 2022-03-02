rule MAL_JSSLoader_Jun_2021_1 {
   meta:
        description = "Detect JSSLoader malware"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-06-04"
        hash1 = "59c6acc8f6771ea6eeb8d8f03832642d87f9aa7eb0c3205398d31ad08e019a9c"
        hash2 = "2609c6ec5d4fdde28d29c272484da66e0995e529cf302ed46f94c68cd99352e3"
        hash3 = "ea167f5460c5f920699e276fb0c51f32c862256415c57edb4bda5760a70b9e4d"
        hash4 = "822457c427a0776b41dd8f3479070e56fdd53ccd0175418d4e7d85065ec7d7d1"
        tlp = "White"
        adversary = "FIN7"
   strings:      
        $s1 = { 8b 45 c8 83 78 0c 00 0f 84 ce 00 00 00 8b 45 c8 8b 4d 08 03 48 0c 8b f4 51 ff 15 [3] 00 3b f4 e8 [2] 00 00 89 45 bc 83 7d bc 00 75 05 e9 a7 00 00 00 8b 45 c8 8b 4d 08 03 48 10 89 4d f8 8b 45 c8 8b 4d 08 03 08 89 4d ec 8b 45 ec 3b 45 08 75 06 8b 45 f8 89 45 ec 8b 45 ec 83 38 00 74 6c 8b 45 ec 8b 08 81 e1 00 00 00 }
        $s2 = { 8b f4 6a 04 68 00 10 00 00 8b 45 c8 8b 4d c8 8b 50 04 2b 11 52 6a 00 ff 15 [3] 00 3b f4 e8 [2] 00 00 89 45 f8 83 7d f8 00 75 05 e9 a7 00 00 00 8b 45 c8 8b 4d c8 8b 50 04 2b 11 52 8b 45 c8 8b 08 51 8b 55 f8 52 e8 [2] 00 00 83 c4 0c 8b f4 8b 45 f8 50 8b fc ff 15 [3] 00 3b fc e8 [2] 00 00 50 ff 15 [3] 00 3b f4 e8 [2] 00 00 8b f4 6a 04 68 00 10 00 00 68 00 11 00 00 6a 00 ff 15 [3] 00 3b f4 e8 [2] 00 00 89 45 ec 83 7d ec 00 75 02 eb 3e 8b 45 c8 8b 48 08 8b 11 89 55 e0 83 7d e0 ff 75 0c c7 85 00 ff ff ff 00 00 00 00 eb 09 8b 45 e0 89 85 00 ff ff ff 8b 8d 00 ff ff ff 8b 55 ec 8b 45 f8 89 04 8a 8b 45 ec 64 a3 2c 00 00 00 5f 5e 5b 81 c4 00 01 00 00 3b ec e8 [2] 00 00 8b e5 5d }
        $s3 = { c7 45 f0 61 00 00 00 c7 45 c8 20 00 00 00 c7 45 cc 88 00 00 00 c7 45 dc 01 00 00 00 8d 45 f0 89 45 d0 33 c0 66 89 45 d4 c7 45 d8 00 00 00 00 c7 45 e0 00 00 00 00 8b 45 08 89 45 e4 8b f4 8d 45 c8 50 ff 15 [3] 00 3b f4 e8 [2] 00 00 89 45 b0 83 7d b0 ff 74 17 8b f4 8d 45 bc 50 8b 4d b0 51 ff 15 [3] 00 3b f4 e8 [2] 00 00 52 8b cd 50 8d 15 2c 13 40 00 e8 [2] 00 00 58 5a 5f 5e 5b 8b 4d fc 33 cd e8 [2] 00 00 81 c4 2c 01 00 00 3b ec e8 [2] 00 00 8b e5 }
        $s4 = { 8b 45 ec 8b 08 81 e1 ff ff 00 00 8b f4 51 8b 55 bc 52 ff 15 [3] 00 3b f4 e8 [2] 00 00 8b 4d f8 89 01 eb 25 8b 45 ec 8b 08 8b 55 08 8d 44 0a 02 8b f4 50 8b 4d bc 51 ff 15 [3] 00 3b f4 e8 [2] 00 00 8b 55 f8 89 02 8b 45 f8 83 c0 04 89 45 f8 8b 45 ec 83 c0 04 89 45 ec eb 8c 8b 45 c8 83 c0 14 89 45 c8 e9 25 ff ff ff 5f 5e 5b 81 c4 08 01 00 00 3b ec e8 [2] 00 00 8b e5 }
     condition:
        uint16(0) == 0x5a4d and filesize > 100KB and filesize < 900KB and all of ($s*)
}
