rule RAN_Conti_May_2021_1 {
   meta:
        description = "Detect packed Conti ransomware (May 2021) [Common parts with Vidar packer, possible false positives to Vidar stealer or Danabot"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-05-19"
        hash1 = "Redacted"
        tlp = "White"
        adversary = "RAAS"
        level = "Experimental"
   strings:      
        $seq1 = { 55 8b ec [3-4] 00 00 [0-5] 56 57 83 3d [4] 25 0f 85 ?? 00 00 00 68 [2] 44 00 ff 15 [2] 42 00 3d f6 65 00 00 0f 85 ?? 00 00 00 6a 00 [0-2] ff 15 2c ?? 42 00 b9 ?? 00 00 00 be [2] 42 00 8d bd f8 f7 ff ff f3 a5 [2-4] 07 00 00 6a 00 8d 85 ?? f8 ff ff 50 e8 [4] 83 c4 0c 8d 4d f8 89 4d fc 6a 00 6a 00 [2-4] 06 00 00 }
        $seq2 = { ff 15 [2] 42 00 8b ?? f4 c1 ?? 04 89 ?? e4 81 3d [4] 8c 07 00 00 75 1d 6a 00 e8 [4] 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 [2] 42 00 8b 45 f8 01 45 e4 8b ?? f4 03 ?? e8 89 ?? f0 81 3d [4] 96 01 }
        $seq3 = { 83 bd [2] ff ff 26 75 05 e8 [2] ff ff 83 3d [4] 7a 75 75 33 ?? 66 89 [3] ff ff 33 ?? 89 [3] ff ff 89 [3] ff ff 89 [3] ff ff 66 89 [3] ff ff 33 ?? 66 89 [3] ff ff 33 ?? 89 [3] ff ff 89 [3] ff ff 89 [3] ff ff 66 89 [3] ff ff 8d [3] ff ff ?? 8d [3] ff ff ?? 8d [3] ff ff ?? ff 15 [2] 42 00 6a 00 ff 15 [2] 42 00 6a 00 6a 00 ff 15 [2] 42 00 e9 50 ff ff }
        $seq4 = { 81 bd [2] ff ff 22 3b 00 00 75 [4-5] 42 00 [5-6] 81 3d [4] e5 05 00 00 75 }
    condition:
         uint16(0) == 0x5a4d and filesize > 90KB and all of ($seq*) 
}
