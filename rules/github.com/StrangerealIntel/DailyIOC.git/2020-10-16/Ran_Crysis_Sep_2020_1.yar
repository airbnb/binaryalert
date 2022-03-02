rule Ran_Crysis_Sep_2020_1 {
   meta:
      description = "Detect Crysis ransomware"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-10-16"
      hash1 = "34c485ad11076ede709ff409c0e1867dc50fd40311ae6e7318ddf50679fa4049"
      hash2 = "4708750c9a6fdeaec5f499a3cd26bb5f61db4f82e66484dc7b44118effbb246f"
      hash3 = "b565c8e1e81796db13409f37e4bd28877272b5e54ab5c0a3d9b6a024e7f5a039"
      hash4 = "8e8b6818423930eea073315743b788aef2f41198961946046b7b89042cb3f95a"
   strings:
      $s1 = { 6f 25 25 4a 72 2e 2e 5c 24 } 
      $s2 = { 52 53 44 53 25 7e 6d }
      $s3 = { 78 78 4a 6f 25 25 5c 72 2e 2e 38 24 }
      $s4 = { 25 65 65 ca af 7a 7a f4 8e ae ae 47 e9 08 08 10 18 ba ba }
      $s5 = { 58 74 1a 1a 34 2e 1b 1b 36 2d 6e 6e dc b2 5a 5a b4 ee a0 a0 5b fb 52 52 a4 f6 3b 3b 76 4d d6 d6 b7 61 b3 b3 7d ce 29 29 52 7b e3 e3 dd 3e 2f 2f 5e 71 84 84 13 97 53 53 }
      $s6 = { 3b 32 32 64 56 3a 3a 74 4e 0a 0a 14 1e 49 49 92 db 06 06 0c 0a 24 24 48 6c 5c 5c b8 e4 c2 c2 9f 5d d3 d3 bd 6e ac ac 43 ef 62 62 }
      $s7 = { 26 4c 6a 26 36 6c 5a 36 3f 7e 41 3f f7 f5 02 f7 cc 83 4f cc 34 68 5c 34 a5 51 f4 a5 e5 d1 34 e5 f1 f9 08 f1 71 e2 93 71 d8 ab 73 d8 31 62 53 31 15 2a 3f 15 04 08 0c 04 c7 95 52 c7 23 46 65 23 }
      $s8 = { 7e fc 82 7e 3d 7a 47 3d 64 c8 ac 64 5d ba e7 5d 19 32 2b 19 73 e6 95 73 60 c0 a0 60 81 19 98 81 4f 9e d1 4f dc a3 7f dc 22 44 66 22 2a 54 7e 2a 90 3b ab 90 88 0b 83 88 46 8c ca 46 ee c7 29 }
      $s9 = "sssssbsss" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 30KB and all of them
}
