rule APT_Lazarus_Loader_Dec_2020_1 {
   meta:
      description = " Detect loader used by Lazarus group in december 2020"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2021-01-26"
      level = "Experimental"
      hash1 = "284df008aa2459fd1e69b1b1c54fb64c534fce86d2704c4d4cc95d72e8c11d6f" // -> Dec 2020
      hash2 = "4c3499f3cc4a4fdc7e67417e055891c78540282dccc57e37a01167dfe351b244" // -> Jan 2021
      // ref dif code -> hash3 = "a4fb20b15efd72f983f0fb3325c0352d8a266a69bb5f6ca2eba0556c3e00bd15" -> Sept 2020
   strings:
   // Entrypoint code template
      $s1 = { 48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 20 49 8b f8 8b da 48 8b f1 83 fa 01 75 05 e8 ?? ?? 00 00 4c 8b c7 8b d3 48 8b ce 48 8b 5c 24 30 48 8b 74 24 38 48 83 c4 20 5f e9 [4] cc cc cc 48 }
      $s2 = { 39 [4] 00 75 07 33 c0 e9 ?? 00 00 00 [8-11] 4? 8b [3] 00 00 ?? 85 c0 74 [4-7] 89 44 24 20 85 ?? 74 17 4c 8b c6 8b d3 49 8b ce e8 ?? ?? ff [1-3] 89 44 24 20 85 c0 75 07 33 c0 e9 ?? 00 00 00 4c 8b c6 8b d3 49 8b ?? e8 [4] 8b f8 89 44 24 20 83 fb 01 75 ?? 85 c0 75 ?? 4c 8b c6 33 d2 49 8b ?? e8 [4] 4c 8b c6 33 d2 49 8b ?? e8 ?? ?? ff ff ?? 8b [6] 85 ?? 74 ?? 4c 8b c6 33 d2 49 8b ?? ff ?? 85 db 74 05 83 fb 03 75 37 4c 8b c6 8b d3 49 8b ?? e8 ?? fd ff ff f7 d8 1b c9 23 cf 8b f9 89 4c 24 20 74 1c 48 8b 05 [2] 00 00 48 85 c0 74 10 4c 8b c6 8b d3 49 8b ?? ff d0 8b f8 89 44 24 20 8b c7 eb }
      $s3 = "ENGINE_get_RANDW" fullword ascii
   // Jmp export
      $s4 = { b8 01 00 00 00 c3 cc cc }
   // Parsing arguments (commandline)
      $s5 = { 33 ?? 48 8d 8c 24 72 02 00 00 33 d2 41 b8 06 02 00 00 89 ?? 24 40 66 89 ?? 24 70 02 00 00 e8 ?? 1b 00 00 48 8d 8c 24 82 04 00 00 33 d2 41 b8 06 02 00 00 66 89 ?? 24 80 04 00 00 e8 ?? 1b 00 00 48 8d 4c 24 51 33 d2 41 b8 03 01 00 00 [2-3] 24 50 e8 ?? 1b 00 00 48 8d 8c 24 61 01 00 00 33 d2 41 b8 03 01 00 00 }
   condition:
      uint16(0) == 0x5a4d and filesize > 50KB and 3 of them
}
