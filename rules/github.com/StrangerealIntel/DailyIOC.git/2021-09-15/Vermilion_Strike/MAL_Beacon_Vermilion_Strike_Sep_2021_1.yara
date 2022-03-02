rule MAL_Beacon_Vermilion_Strike_Sep_2021_1 {
   meta:
        description = "Detect the windows version of the beacon of Vermilion Strike implant"
        author = "Arkbird_SOLG"
        reference1 = "https://www.intezer.com/blog/malware-analysis/vermilionstrike-reimplementation-cobaltstrike/"
        date = "2021-09-14"
        hash1 = "c49631db0b2e41125ccade68a0fe7fb70939315f1c580510e40e5b30ead868f5"
        hash2 = "07b815cee2b85a41820cd8157a68f35aa1ed0aa5f4093b8cb79a1d645a16273f"
        hash3 = "7129434afc1fec276525acfeee5bb08923ccd9b32269638a54c7b452f5493492"
        tlp = "White"
        adversary = "Vermilion Strike"
    strings:
        $s1 = { 50 c7 03 01 00 00 00 e8 cc ?? 00 00 89 43 04 83 f8 ff 74 2c 8b 4d 08 6a 00 8d 44 24 0c 50 53 6a 08 6a 01 51 e8 91 ?? 00 00 85 c0 75 13 8b 44 24 08 66 83 78 08 01 6a 01 50 74 38 e8 80 ?? 00 00 8b 4e 10 2b 4e 0c b8 93 24 49 92 f7 e9 03 d1 c1 fa 04 8b c2 c1 e8 1f 47 03 c2 3b f8 0f 8c 30 ff ff ff 53 ff 15 }
        $s2 = { 8b 4c 24 1c 6a 00 6a 00 6a 00 6a 01 51 ff 15 5c a2 02 10 8b 55 0c 8b f0 56 6a 02 53 52 8b cf 89 74 24 34 e8 f0 fb ff ff 8b 45 0c 83 c4 10 6a 00 6a 00 6a 03 6a 00 6a 00 50 57 56 ff 15 50 a2 02 10 8b 4c 24 30 6a 00 68 00 82 80 80 6a 00 6a 00 6a 00 53 51 50 89 44 24 3c ff 15 64 a2 02 10 8b f8 89 7c 24 14 8d 49 00 8b b4 24 90 00 00 00 8b 5c 24 7c 8b c3 83 fe 10 73 04 8d 44 24 7c 8d 50 01 8d a4 24 00 00 00 00 8a 08 40 84 c9 75 f9 2b c2 8b cb 83 fe 10 73 04 8d 4c 24 7c 8b 55 20 52 8b 54 24 2c 52 50 51 57 ff 15 4c a2 02 10 85 }
        $s3 = { 68 00 00 00 10 6a 00 6a 00 6a 00 6a 00 c7 44 24 60 01 00 00 00 ff 15 40 a2 02 10 8b d8 8d 54 24 2c 52 8d 44 24 3c 50 55 53 ff 15 38 a2 02 10 8b e8 85 db 74 07 53 ff 15 44 a2 02 10 85 ed 74 2f 8b }
        $s4 = { 6a ff 68 [2] 02 10 64 a1 00 00 00 00 50 81 ec 14 01 00 00 a1 c0 72 03 10 33 c4 89 84 24 10 01 00 00 53 a1 c0 72 03 10 33 c4 50 8d 84 24 1c 01 00 00 64 a3 00 00 00 00 33 db 8d 44 24 0c 89 9c 24 24 01 00 00 50 8d 4c 24 18 89 5c 24 0c 51 89 74 24 18 c7 44 24 14 04 01 00 00 ff 15 04 a0 02 10 8d 44 24 14 c7 46 18 0f 00 00 00 89 5e 14 88 5e 04 8d 50 01 8a 08 40 3a cb 75 f9 2b c2 50 8d 54 24 18 52 8b ce e8 [2] ff ff 89 9c 24 24 01 00 00 c7 44 24 08 01 00 00 00 e8 d1 fe ff ff 85 c0 8b c6 74 0e 6a 02 68 ?? c6 02 10 e8 [2] ff ff 8b c6 8b 8c 24 1c 01 00 00 64 89 0d 00 00 00 00 59 5b 8b 8c 24 }
        $s5 = { a1 c0 72 03 10 33 c4 89 44 24 2c 68 00 00 00 f0 6a 18 6a 00 6a 00 68 4c 97 03 10 ff 15 30 a0 02 10 85 c0 75 11 33 c0 8b 4c 24 2c 33 cc e8 [2] 00 00 83 c4 30 c3 8b 15 58 97 03 10 8b 0d 54 97 03 10 68 50 97 03 10 6a 00 33 c0 6a 00 66 89 44 24 1e a1 5c 97 03 10 89 54 24 2c 6a 1c 8d 54 24 20 89 44 24 34 a1 4c 97 03 10 89 4c 24 2c 8b 0d 60 97 03 10 52 50 c6 44 24 28 08 c6 44 24 29 02 c7 44 24 2c 0e 66 00 00 c7 44 24 30 10 00 00 00 89 4c 24 40 ff 15 2c a0 02 10 85 c0 74 87 8b 0d 50 97 03 10 56 8b 35 38 a0 02 10 6a 00 68 ?? 82 03 10 6a 01 51 c7 44 24 18 01 00 00 00 c7 44 24 20 01 00 00 00 ff d6 85 c0 74 2b a1 50 97 03 10 6a 00 8d 54 24 0c 52 6a 03 50 ff d6 85 c0 74 16 8b 15 50 97 03 10 6a 00 8d 4c 24 14 51 6a 04 52 ff d6 85 c0 75 12 33 c0 5e 8b 4c 24 2c 33 cc e8 [2] 00 00 83 c4 30 c3 8b 15 50 97 03 10 6a }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and 4 of ($s*)
}
