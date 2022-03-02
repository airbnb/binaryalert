rule RAN_Piton_Nov_2021_1 {
    meta:
        description = "Detect Piton variant (rebuild from the Babuk leaks)"
        author = "Arkbird_SOLG"
        reference ="Internal Research"
        date = "2021-11-03"
        hash1 = "71936bc3ee40c7ea678889d2ad5fa7eb39401752cd58988ce462f9d4048578ac"
        hash2 = "77c7839c7e8d4aaf52e33a2f29db8459381b5cc3b2700072305a8bae5e0762a9"
        hash3 = "ae6020a06d2a95cbe91b439f4433e87d198547dec629ab0900ccfe17e729cff1"
        tlp = "white"
        adversary = "RAAS"
    strings:
        $s1 = { 68 38 3c 40 00 6a 00 68 01 00 1f 00 ff 15 c4 50 41 00 85 c0 75 11 68 58 3c 40 00 6a 00 6a 00 ff 15 98 50 41 00 eb 0a e9 b0 00 00 00 e9 ab 00 00 00 c7 45 a8 00 00 00 00 68 78 3c 40 00 8b 55 c8 52 8b 45 e8 50 e8 86 9b ff ff 83 c4 0c 0f b6 c8 83 f9 01 75 0c 8b 55 a8 52 e8 02 f9 ff ff 83 c4 04 e8 ea 94 ff ff ff 15 04 51 41 00 89 45 c0 83 7d c0 00 74 3f b8 41 00 00 00 66 89 45 f0 eb 0c 66 8b 4d f0 66 83 c1 01 66 89 4d f0 0f b7 55 f0 83 fa 5a 7f 1f 8b 45 c0 83 e0 01 74 }
        $s2 = { 68 80 16 40 00 ff 15 38 50 41 00 89 45 f0 68 90 16 40 00 8b 45 f0 50 ff 15 34 50 41 00 89 45 fc 83 7d fc 00 74 07 8d 4d f8 51 ff 55 fc 6a 00 6a 00 68 b0 16 40 00 68 08 17 40 00 68 18 17 40 00 6a 00 ff 15 4c 51 41 00 e8 9d 03 00 00 85 c0 74 2d 68 24 17 40 00 ff 15 38 50 41 00 89 45 ec 68 34 17 40 00 8b 55 ec 52 ff 15 34 50 41 00 89 45 f4 83 7d }
        $s3 = { 81 ec f4 02 00 00 c7 85 7c ff ff ff 90 15 40 00 c7 45 80 98 15 40 00 c7 45 84 a0 15 40 00 c7 45 88 a8 15 40 00 c7 45 8c b0 15 40 00 c7 45 90 b8 15 40 00 c7 45 94 c0 15 40 00 c7 45 98 c8 15 40 00 c7 45 9c d0 15 40 00 c7 45 a0 d8 15 40 00 c7 45 a4 e0 15 40 00 c7 45 a8 e8 15 40 00 c7 45 ac f0 15 40 00 c7 45 b0 f8 15 40 00 c7 45 b4 00 16 40 00 c7 45 b8 08 16 40 00 c7 45 bc 10 16 40 00 c7 45 c0 18 16 40 00 c7 45 c4 20 16 40 00 c7 45 c8 28 16 40 00 c7 45 cc 30 16 40 00 c7 45 d0 38 16 40 00 c7 45 d4 40 16 40 00 c7 45 d8 48 16 40 00 c7 45 dc 50 16 40 00 c7 45 e0 58 16 40 00 c7 45 fc 00 00 00 00 c7 45 e4 78 00 00 00 c7 45 e8 00 00 00 00 c7 45 f4 00 00 00 00 eb 09 8b 45 f4 83 c0 01 89 45 f4 83 7d f4 1a 7d 35 8b 4d f4 8b 94 8d 7c ff ff ff 52 ff 15 f8 50 41 00 83 f8 01 75 1d 8b 45 fc 8b 4d f4 8b 94 8d 7c ff ff ff 89 94 85 14 ff ff ff 8b 45 fc 83 c0 01 89 45 fc eb bc b9 02 00 00 00 6b d1 00 33 c0 66 89 84 15 0c fd ff ff 68 00 00 01 00 e8 00 e8 00 00 83 c4 04 89 45 f8 83 7d f8 00 0f 84 d4 00 00 00 68 00 00 01 00 e8 e6 e7 00 00 83 c4 04 89 45 ec 83 7d ec 00 0f 84 ae 00 00 00 68 00 80 00 00 8b 4d f8 51 ff 15 08 51 41 00 89 45 f0 83 7d fc 00 76 63 8d 55 e8 52 8b 45 e4 50 8d 8d 0c fd ff ff 51 8b 55 f8 52 ff 15 f4 50 41 00 85 c0 74 26 8d 85 0c fd ff ff 50 ff 15 40 50 41 00 83 f8 03 75 14 b9 02 00 00 00 6b d1 00 33 c0 66 89 84 15 0c fd ff ff eb 22 8b 4d fc 83 e9 01 89 4d fc 8b 55 f8 52 8b 45 fc 8b 8c 85 14 ff ff ff 51 ff 15 44 50 41 00 eb 02 eb 1b 68 00 80 00 00 8b 55 f8 52 8b 45 f0 50 ff 15 00 51 41 00 85 c0 0f 85 7a ff ff ff 8b 4d f0 51 ff 15 fc 50 41 00 8b 55 }
    condition:
        uint16(0) == 0x5a4d and filesize > 30KB and all of them
}
