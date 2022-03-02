rule APT_APT27_Hyperbro_Apr_2021_1 {
   meta:
        description = "Detect Hyperbro backdoor"
        author = "Arkbird_SOLG"
        reference = "-"
        date = "2021-05-01"
        hash1 = "36fad80a5f328f487b20a3f5fc5f1902d50cbb1bd9167c44b66929a1288fc6f4"
        hash2 = "52072a8f99dacd5c293fccd051eab95516d8b880cd2bc5a7e0f4a30d008e22a7"
        hash3 = "9000ce3c0e01b6c80edb3af87aad8117513ce334135aa7d7b1c2afa067f4c4ab"
        hash4 = "92bbcb5461ab5959e31f997a6df77995377d69f8077e43e5812fcbe9303d831c"
        tlp = "White"
        adversary = "APT27"
   strings:
        $seq1 = { 8b [5] 7? 0? [2] 0? ?? 0? [3] ff 75 0? [11] 5? [2] 0? ?? 8b }
        // version 1
        $seq2 = { e8 ?? 0? 00 00 b0 01 c3 55 8b ec ff 75 08 ff 15 34 c0 00 10 85 c0 74 11 56 8b 30 50 e8 ?? 1? 00 00 8b c6 59 85 f6 75 f1 5e 5d c3 cc 8b 4c 24 0c 0f b6 44 24 08 8b d7 8b 7c 24 04 85 c9 0f 84 3c 01 00 00 69 c0 01 01 01 01 83 f9 20 0f 8e df 00 00 00 81 f9 80 00 00 00 0f 8c 8b 00 00 00 0f ba 25 b8 27 01 10 01 73 09 f3 aa 8b 44 24 04 8b fa c3 0f ba 25 10 20 01 10 01 0f 83 b2 00 00 00 66 0f 6e c0 66 }
        // version 2
        $seq3 = { 8b 44 24 08 48 75 [13] be ?? 16 00 10 bb 00 10 00 10 05 [2] 00 00 2b f3 [0-3] 74 0? 8? [0-2] cf [0-4] 03 cb ?? 11 47 3b fe 72 ?? e8 ?? fd ff ff 5f 5e 5b 33 c0 40 c2 0c 00 8b ff 55 8b ec 8b 45 0c 56 57 83 f8 01 75 7c 50 e8 1c 14 00 00 59 85 c0 75 07 33 c0 e9 0e 01 00 00 e8 a6 06 00 00 85 c0 75 07 e8 32 14 00 00 eb e9 e8 af 13 00 00 ff 15 ?? 80 00 10 a3 18 b8 00 10 e8 68 12 00 00 a3 64 ac 00 10 e8 89 0c 00 00 85 c0 7d 07 e8 1f 03 00 00 eb cf e8 93 11 00 00 85 c0 7c 20 e8 12 0f 00 00 85 c0 7c 17 6a 00 e8 41 0a 00 00 59 85 c0 75 0b ff 05 60 ac 00 10 e9 a8 00 00 00 e8 a4 0e 00 00 eb c9 33 ff 3b c7 75 31 39 3d 60 ac 00 10 7e 81 ff 0d 60 ac 00 10 39 3d b4 ac 00 10 75 05 e8 d0 0b 00 00 39 7d 10 75 7b e8 77 0e 00 00 e8 bd 02 00 00 e8 a1 13 00 00 eb 6a 83 f8 02 75 59 e8 78 02 00 00 68 14 02 00 00 6a 01 e8 54 08 00 00 8b f0 59 59 3b f7 0f 84 36 ff ff ff 56 ff 35 00 a0 00 10 ff 35 7c ac 00 10 e8 d3 01 00 00 59 ff d0 85 c0 74 17 57 56 e8 b1 02 00 00 59 59 ff 15 ?? 80 00 10 83 4e 04 ff 89 06 eb 18 56 e8 3f 07 00 00 59 e9 fa fe ff ff 83 f8 03 75 07 57 e8 33 05 00 00 59 33 c0 40 5f 5e 5d c2 0c 00 6a 0c 68 d0 92 00 10 e8 ?? 15 00 00 8b f9 8b f2 8b 5d 08 33 c0 40 89 45 e4 85 f6 75 0c 39 15 60 ac 00 10 0f 84 c5 00 00 00 83 65 fc 00 3b f0 74 05 83 fe 02 75 2e a1 ?? 81 00 10 85 c0 74 08 57 56 53 ff d0 89 45 e4 83 7d e4 00 0f 84 96 00 00 00 57 56 53 e8 72 fe ff ff 89 45 e4 }
   condition:
     uint16(0) == 0x5a4d and filesize > 10KB and 2 of ($seq*)
}
