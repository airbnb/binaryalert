rule ATM_DispCashBR_May_2021_1 {
   meta:
        description = "Detect the DispCashBR ATM malware"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2020-05-14"
        hash1 = "432f732a4ecbb86cb3dedbfa881f2733d20cbcc5958ead52823bf0967c133175"
        hash2 = "7cea6510434f2c8f28c9dbada7973449bb1f844cfe589cdc103c9946c2673036"
        tlp = "White"
        adversary = "-"
   strings:
          $seq1 = { c7 45 cc 00 00 00 00 c7 04 24 68 5d 40 00 e8 40 0e 00 00 8b 85 a0 fd ff ff 8b 40 0a 8b 40 03 89 44 24 04 c7 04 24 89 5d 40 00 e8 0c 0e 00 00 c7 04 24 a4 5d 40 00 e8 18 0e 00 00 8b 85 a0 fd ff ff 8b 40 0a 8b 40 03 01 45 cc c7 04 24 d0 07 00 00 e8 7d 0e 00 00 83 ec 04 8b 85 a0 fd ff ff 8d 48 0a 0f b7 85 be fd ff ff 0f b7 c0 8d 95 98 fd ff ff 89 54 24 10 c7 44 24 0c 00 00 00 00 89 4c 24 08 c7 44 24 04 2e 01 00 00 89 04 24 e8 75 05 00 00 83 ec 14 89 45 e8 8b 45 e8 83 c0 38 83 }
          $seq2 = { 0f b7 85 be fd ff ff 0f b7 c0 8b 55 e4 89 54 24 08 c7 44 24 04 06 00 00 00 89 04 24 e8 7e 17 00 00 83 ec 0c 0f b7 85 be fd ff ff 0f b7 c0 8d 95 b8 fd ff ff 89 54 24 08 c7 44 24 04 00 00 00 00 89 04 24 e8 5f 17 00 00 83 ec 0c 0f b7 85 be fd ff ff 0f b7 c0 8d 95 26 fd ff ff 89 54 24 10 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 2e 01 00 00 89 04 24 e8 f8 16 00 00 83 ec 14 89 45 e0 8d 85 ac fd ff ff 89 44 24 08 c7 44 24 04 03 00 00 00 c7 04 24 04 00 00 00 e8 dc 16 00 00 83 ec 0c 8b 45 e0 83 c0 38 83 f8 }
          $seq3 = { 8b 85 a8 fd ff ff 8b 50 14 8b 85 a8 fd ff ff 8b 40 10 0f af c2 89 45 d8 8b 45 d8 89 44 24 04 c7 04 24 04 5b 40 00 e8 aa 12 00 00 8b 85 a4 fd ff ff 0f b7 40 04 0f b7 c0 89 44 24 04 c7 04 24 24 5b 40 00 e8 8d 12 00 00 8b 85 a8 fd ff ff 8b 50 18 8b 85 a8 fd ff ff 8b 40 1c 0f af c2 89 45 d4 c7 45 f0 00 00 00 00 8b 45 d8 89 44 24 04 c7 04 24 45 5b 40 00 e8 5b 12 00 00 83 45 f0 01 83 7d f0 01 7e e3 8b 85 a0 fd ff ff c7 40 06 01 00 00 00 0f b7 85 be fd ff ff 0f b7 c0 8d 95 26 fd ff ff 89 54 24 10 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 2e 01 00 00 89 04 24 e8 60 ed ff ff 89 45 d0 }
          $seq4 = { c7 45 ec 00 00 00 00 8d 85 c4 fd ff ff 89 44 24 04 c7 04 24 03 00 02 0b e8 47 1b 00 00 83 ec 08 89 45 e8 83 7d e8 00 74 18 c7 04 24 92 50 40 00 e8 8b 23 00 00 c7 04 24 ff ff ff ff e8 8f 23 00 00 c7 04 24 aa 50 40 00 e8 8b 23 00 00 c7 04 24 f5 ff ff ff e8 ef 23 00 00 83 ec 04 c7 44 24 04 03 00 00 00 89 04 24 e8 e4 23 00 00 83 ec 08 c7 04 24 b8 0b 00 00 e8 dd 23 00 00 83 ec 04 c7 04 24 c4 50 40 00 e8 4e 23 00 00 8d 85 c4 fd ff ff 83 c0 06 89 44 24 04 c7 04 24 ed 50 40 00 e8 1d 23 00 00 8d 85 c4 fd ff ff 05 07 01 00 00 89 44 24 04 c7 04 24 03 51 40 00 e8 02 23 00 00 0f b7 85 c8 fd ff ff 0f b7 c0 89 44 24 04 c7 04 24 1a 51 40 00 e8 e8 22 00 00 0f b7 85 c6 fd ff ff 0f b7 c0 89 44 24 04 c7 04 24 2f 51 40 00 e8 ce 22 00 00 0f b7 85 c4 fd ff ff 0f b7 c0 89 44 24 04 c7 04 24 42 51 40 00 e8 b4 22 00 00 c7 04 24 54 51 40 00 e8 c0 22 00 00 8d 85 c0 fd ff ff 89 04 24 e8 46 1a 00 00 83 ec 04 8b 85 c0 fd ff ff 8d 95 be fd ff ff 89 54 24 20 c7 44 24 1c 00 00 00 00 8d 95 c4 fd ff ff 89 54 24 18 c7 44 24 14 0f 00 02 0b c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 89 44 24 04 c7 04 24 7f 51 40 00 e8 f9 19 00 00 83 ec 24 89 45 e8 8b 45 e8 83 c0 36 83 f8 }        
   condition:
         uint16(0) == 0x5a4d and filesize > 20KB and 3 of ($seq*)
}
