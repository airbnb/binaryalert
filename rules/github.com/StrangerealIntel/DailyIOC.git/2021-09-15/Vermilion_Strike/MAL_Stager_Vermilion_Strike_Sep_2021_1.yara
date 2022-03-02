rule MAL_Stager_Vermilion_Strike_Sep_2021_1 {
   meta:
        description = "Detect the windows version of the stager of Vermilion Strike implant"
        author = "Arkbird_SOLG"
        reference1 = "https://www.intezer.com/blog/malware-analysis/vermilionstrike-reimplementation-cobaltstrike/"
        date = "2021-09-14"
        hash1 = "3ad119d4f2f1d8ce3851181120a292f41189e4417ad20a6c86b6f45f6a9fbcfc"
        level = "experimental"
        tlp = "White"
        adversary = "Vermilion Strike"
    strings:
        $s1 = { a1 b0 62 41 00 33 c4 50 8d 84 24 d0 00 00 00 64 a3 00 00 00 00 8b da 8b 84 24 ec 00 00 00 8b b4 24 e0 00 00 00 8b bc 24 e4 00 00 00 8b ac 24 e8 00 00 00 8d 54 24 2c 52 89 44 24 28 89 4c 24 2c e8 95 f0 ff ff 33 c0 89 84 24 d8 00 00 00 c7 84 24 88 00 00 00 0f 00 00 00 89 84 24 84 00 00 00 88 44 24 74 6a 17 68 fc 3b 41 00 8d 44 24 78 c6 84 24 e0 00 00 00 01 e8 9e 0b 00 00 6a 02 68 14 3c 41 00 8d 44 24 78 e8 8e 0b 00 00 6a 00 6a 00 6a 00 6a 01 55 ff 15 44 21 41 00 8b e8 55 6a 02 57 53 8b ce 89 6c 24 2c e8 8d fc ff ff 83 c4 10 6a 00 6a 00 6a 03 6a 00 6a 00 53 56 55 ff 15 58 21 41 00 6a 00 68 00 82 80 80 6a 00 6a 00 6a 00 57 68 f8 3b 41 00 50 89 44 24 40 ff 15 4c 21 41 00 }
        $s2 = { 64 a1 00 00 00 00 50 83 ec 60 a1 b0 62 41 00 33 c4 89 44 24 58 53 55 56 57 a1 b0 62 41 00 33 c4 50 8d 44 24 74 64 a3 00 00 00 00 8b 84 24 88 00 00 00 8b ac 24 84 00 00 00 8b f9 89 44 24 18 33 c0 8d 4c 24 1c 51 8b f2 33 db 89 44 24 30 89 44 24 34 89 44 24 38 89 44 24 3c 89 44 24 40 89 44 24 44 89 44 24 48 89 44 24 4c 89 44 24 50 89 44 24 20 89 44 24 24 89 44 24 28 89 44 24 2c ff 15 2c 21 41 00 85 c0 74 21 39 5c 24 1c 74 05 bb 01 00 00 00 8b 44 24 20 }
        $s3 = { 50 56 8d 4c 24 58 e8 fc f2 ff ff 6a 01 8d 54 24 18 52 8d 44 24 58 50 89 9c 24 88 00 00 00 33 c0 c6 44 24 20 3d e8 0d 01 00 00 83 f8 ff 74 4f 80 bc 24 8c 00 00 00 00 74 16 56 bb 18 3c 41 00 8d 7c 24 54 e8 8f fd ff ff 83 c4 04 84 c0 75 2f 56 bb 20 3c 41 00 8d 7c 24 54 e8 79 fd ff ff 83 c4 04 84 c0 75 19 56 bb 28 3c 41 00 e8 67 fd ff ff 83 c4 04 84 c0 74 07 c7 45 00 04 00 00 00 83 7c 24 68 10 72 19 }
        $s4 = { 8d 44 24 18 50 8d 4c 24 18 51 6a 1f 53 c7 44 24 28 04 00 00 00 ff 15 3c 21 41 00 81 4c 24 14 00 01 00 00 6a 04 8d 54 24 18 52 6a 1f 53 }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and 3 of them
}
