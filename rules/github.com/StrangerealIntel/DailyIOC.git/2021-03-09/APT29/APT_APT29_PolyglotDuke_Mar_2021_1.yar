rule APT_APT29_PolyglotDuke_Mar_2021_1 {
   meta:
      description = "Detect PolyglotDuke implant used by APT29 group"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2021-03-08"
      hash1 = "9b33ec7f5e615a6556f147b611425d3ca4a8879ce746d4a8cb62adf4c7f76029"
      hash2 = "0c39fce5bd32b4f91a1df4f6321c2f01c017195659c7e95a235ef71ca2865aa9"
   strings:
      // seq Mutex
      $seq1 = { 48 83 ec 28 48 8b 05 [2] 02 00 48 33 05 [2] 02 00 74 02 ff d0 48 83 c4 28 c3 cc 48 83 ec 28 48 8b 05 [2] 02 00 48 33 05 [2] 02 00 74 02 ff d0 48 83 c4 28 c3 cc 4c 8b 15 [2] 02 00 41 8b c0 4c 33 15 [2] 02 00 74 03 49 ff e2 83 e0 01 4c 8b ca 41 83 e0 02 8b d0 48 ff 25 [2] 01 00 cc cc cc 4c 8b 15 [2] 02 00 4c 33 15 [2] 02 00 74 03 49 ff e2 48 ff 25 [2] 01 00 cc cc 48 83 ec 28 48 8b 05 [2] 02 00 48 33 05 [2] 02 00 74 07 48 83 c4 28 48 ff e0 b9 78 00 00 00 ff 15 [2] 01 00 32 c0 48 83 c4 28 c3 cc cc cc 48 8b 05 [2] 02 00 48 33 05 [2] 02 00 74 03 48 ff e0 33 c0 c3 cc cc 48 8b 05 [2] 02 00 48 33 05 [2] 02 00 74 03 48 ff e0 }
      // seq OEM code page
      $seq2 = { 48 8b c4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 57 48 83 ec 30 33 ff 48 8b da 48 8b f1 48 85 c9 75 18 e8 69 0c 00 00 bb 16 00 00 00 89 18 e8 b1 38 00 00 8b c3 e9 a7 00 00 00 48 85 d2 74 e3 e8 a8 3f 00 00 41 bf 01 00 00 00 85 c0 75 0c ff 15 [2] 01 00 85 c0 41 0f 44 ff 83 64 24 28 00 48 83 23 00 48 83 64 24 20 00 41 83 c9 ff 4c 8b c6 33 d2 8b cf ff 15 [2] 01 00 48 63 e8 85 c0 75 11 ff 15 [2] 01 00 8b c8 e8 b2 0b 00 00 33 c0 eb 4f 48 8b cd 48 03 c9 e8 e3 07 00 00 48 89 03 48 85 c0 74 e9 41 83 c9 ff 4c 8b c6 33 d2 8b cf 89 6c 24 28 48 89 44 24 20 ff 15 [2] 01 00 85 c0 75 1b ff 15 [2] 01 00 8b c8 e8 70 0b 00 00 48 8b 0b e8 ?? f3 ff ff 48 83 23 00 eb b0 41 8b c7 48 8b 5c 24 40 48 8b 6c 24 48 48 8b 74 24 50 48 8b 7c 24 58 48 83 c4 30 41 5f c3 48 8b c4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 57 48 83 ec 40 33 ff 48 8b da 48 8b f1 } 
      // seq jump dll
      $seq3  = { ff 25 00 00 00 00 00 00 00 00 00 00 00 00 cc }
      $seq4 = "InitSvc" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 100KB and 3 of them 
}
