rule APT_Molerats_Feb_2021_1 {
   meta:
      description = "Detect Molerats implants"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2021-02-27"
      hash1 = "0a55551ade55705d4be6e946ab58a26d7cf8087558894af8799931b09d38f3bc"
      hash2 = "c9d7b5d06cd8ab1a01bf0c5bf41ef2a388e41b4c66b1728494f86ed255a95d48"
   strings:
      // sequence for getting input locale identifier
      $seq1 = { 55 8b ec 81 c4 60 fc ff ff 53 33 d2 89 95 60 fc ff ff 89 45 fc 33 c0 55 68 [1-3] 00 64 ff 30 64 89 20 8b 45 fc 83 78 44 00 0f 85 5d 01 00 00 b2 01 a1 [2] 44 00 e8 [3] ff 8b 55 fc 89 42 44 8b 45 fc 83 c0 48 e8 [3] ff 8d 85 ec fe ff ff 50 6a 40 e8 [3] ff 48 85 c0 0f 8c 18 01 00 00 40 89 45 f0 8d 85 ec fe ff ff 89 45 ec 8b 45 ec 8b 00 e8 35 ?? f5 ff 84 c0 0f 84 ec 00 00 00 8d 45 f4 50 68 19 00 02 00 6a 00 6a 00 8b 45 ec 0f b7 00 89 85 64 fc ff ff c6 85 68 fc ff ff 00 8d 8d 64 fc ff ff ba [3] 00 8d 85 6c fc ff ff e8 [3] ff 50 68 02 00 00 80 e8 [3] ff 85 c0 0f 85 a3 00 00 00 33 c0 55 68 [3] 00 64 ff 30 64 89 20 c7 45 f8 00 02 00 00 8d 45 f8 50 8d 85 ec fc ff ff 50 6a 00 6a 00 68 [3] 00 8b 45 f4 50 e8 [3] ff 85 c0 75 4f 8d 85 60 fc ff ff 8d 95 ec fc ff ff b9 00 01 00 00 e8 [3] ff 8b 95 60 fc ff ff 8b 45 ec 8b 08 8b 45 fc 8b 40 44 8b 18 ff 53 40 8b 45 ec 8b 00 8b 55 fc 3b 42 4c 75 16 8b 45 fc 83 c0 48 8d 95 ec fc ff ff b9 00 01 00 00 e8 [3] ff 33 c0 5a 59 59 64 89 10 68 [3] 00 8b 45 f4 50 e8 [3] ff }
      // sequence on the checking process on the registry
      $seq2= { 55 8b ec 81 c4 e4 fd ff ff 53 8b da 89 45 fc 8b 45 fc e8 [2] ff ff 33 c0 55 68 [2] 40 00 64 ff 30 64 89 20 83 7d fc 00 75 15 68 05 01 00 00 8d 85 e6 fd ff ff 50 6a 00 e8 [2] ff ff eb 1a 8b 45 fc e8 [2] ff ff 8b c8 8d 85 e6 fd ff ff ba 05 01 00 00 e8 da f7 ff ff 66 83 bd e6 fd ff ff 00 0f 84 a7 01 00 00 33 c0 89 45 f8 8d 45 f4 50 68 19 00 0f 00 6a 00 68 [2] 40 00 68 01 00 00 80 e8 [2] ff ff 85 c0 0f 84 9a 00 00 00 8d 45 f4 50 68 19 00 0f 00 6a 00 68 [2] 40 00 68 02 00 00 80 e8 2b 5e ff ff 85 c0 74 7c 8d 45 f4 50 68 19 00 0f 00 6a 00 68 70 f6 40 00 68 01 00 00 80 e8 0d 5e ff ff 85 c0 74 5e 8d 45 f4 50 68 19 00 0f 00 6a 00 68 70 f6 40 00 68 02 00 00 80 e8 [2] ff ff 85 c0 74 40 8d 45 f4 50 68 19 00 0f 00 6a 00 68 [2] 40 00 68 01 00 00 80 e8 [2] ff ff 85 c0 74 22 8d 45 f4 50 68 19 00 0f 00 6a 00 68 [2] 40 00 68 01 00 00 80 e8 [2] ff ff 85 c0 0f 85 e6 00 00 00 33 c0 55 68 [2] 40 00 64 ff 30 64 89 20 8d 85 e6 fd ff ff ba 05 01 00 00 e8 c9 fc ff ff 8d 45 f0 50 6a 00 6a 00 6a 00 8d 85 e6 fd ff ff 50 8b 45 f4 50 e8 [2] ff ff 85 c0 75 33 8b 45 f0 e8 [2] ff ff 89 45 f8 8d 45 f0 50 8b 45 f8 50 6a 00 6a 00 8d 85 e6 fd ff ff 50 8b 45 f4 50 e8 [2] ff ff 8b c3 8b 55 f8 e8 [2] ff ff eb 4b 8d 45 f0 50 6a 00 6a 00 6a 00 68 [2] 40 00 8b 45 f4 50 e8 [2] ff ff 85 c0 75 2f 8b 45 f0 e8 [2] ff ff 89 45 f8 8d 45 f0 50 8b 45 f8 50 6a 00 6a 00 68 [2] 40 00 8b 45 f4 50 e8 [2] ff ff 8b c3 8b 55 f8 e8 [2] ff ff 33 c0 5a 59 59 64 89 10 68 [2] 40 00 83 7d f8 00 74 08 8b 45 f8 e8 [2] ff ff 8b 45 f4 50 e8 [2] ff ff }
      // sequence taking screenshot
      $seq3 = { d1 f8 79 03 83 d0 00 03 45 80 89 45 d0 8b 45 a4 8b 80 e4 02 00 00 8b 40 10 01 45 d0 8b 45 a4 8b 80 e4 02 00 00 8b 40 04 29 45 d0 8b 75 8c 2b 75 d4 83 ee 02 8b 45 a4 8b 80 e4 02 00 00 2b 70 08 8b 45 a4 8b 80 e4 02 00 00 2b 70 0c 89 75 8c 6a 00 56 8b 45 d0 50 8b 45 ec e8 [2] fb ff 50 57 8b 85 68 ff ff ff 50 e8 [2] fc ff 84 db 0f 84 0d 03 00 00 a1 [3] 00 8b 00 e8 [2] 09 00 50 8b 45 b4 50 6a 23 e8 [3] ff 89 45 d8 8b 45 d8 01 45 90 83 45 94 0f 83 45 90 05 8b 45 f0 8b 40 08 8b 50 74 }
      $s1 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" fullword wide
      $s2 = { 45 00 72 00 72 00 6f 00 72 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 3a 00 20 00 25 00 73 } // Error connecting to server: %s
      $s3 = { 45 00 72 00 72 00 6f 00 72 00 20 00 6f 00 70 00 65 00 6e 00 69 00 6e 00 67 00 20 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 3a 00 20 00 28 00 25 00 64 00 29 00 20 00 25 00 73 } // Error opening request: (%d) %s
      $s4 = { 43 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 6f 00 70 00 65 00 6e 00 20 00 66 00 69 00 6c 00 65 00 20 00 22 00 25 00 73 00 22 00 2e 00 20 00 25 00 73 } // Cannot open file "%s". %s
      $s5 = { 43 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 6f 00 70 00 65 00 6e 00 20 00 63 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 3a 00 20 00 25 00 73 } // Cannot open clipboard: %s
   condition:
      uint16(0) == 0x5a4d and filesize > 500KB and 2 of ($seq*) and 3 of ($s*)
}
