rule APT_AridViper_Installer_Feb_2020_1 {
   meta:
      description = "Detect Installer used by AridViper group in Febuary 2021"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2021-02-08"
      level = "Experimental"
      hash1 = "16ed131c4a7545495dc3f07d199748a5d0560e7c8a44493c1906163bedc9c2e0" // -> Feb 2021
      hash2 = "84d9c7852b87253ccf0ca1aad57e510a4badfe253c063a72c7751930f0279c83" // -> Dec 2020
   strings:
     // Sequence on the parsing db
      $seq_db = { 8b 7d ec 33 d2 89 55 ec 8b 0f 8b c1 89 4d e4 38 11 74 2e 66 90 83 f8 ff 73 24 8a 08 40 80 f9 c0 72 16 8a 08 80 e1 c0 80 f9 80 75 0c 8a 48 01 40 80 e1 c0 80 f9 80 74 f4 42 80 38 00 75 d7 89 55 ec f7 46 18 00 00 08 00 74 47 8b d7 8b cb e8 a2 f9 ff ff 89 45 e0 85 c0 74 34 83 7d f0 01 b9 [3] 00 50 ff 75 f8 b8 [3] 00 ff 75 e4 0f 44 c8 51 ff 75 f4 68 [3] 00 53 e8 34 2e 00 00 8b 55 e0 83 c4 1c 8b ce e8 ?? c3 fc ff 8b 55 ec ff 75 e4 8b 45 f8 b9 [3] 00 83 7d f0 01 52 50 50 50 50 50 b8 [3] 00 0f 44 c1 50 ff 75 f4 68 [3] 00 53 e8 f8 2d 00 00 83 c4 2c ba [3] 00 8b ce ff 75 f4 e8 e6 2e 00 00 83 c4 04 85 c0 74 16 ff 37 ff 75 f8 ff 75 f4 68 [3] 00 53 e8 cc 2d 00 00 83 c4 14 8b d7 8b cb e8 90 f9 ff ff 89 45 e0 85 c0 74 1e 50 8b 45 f8 50 50 68 [3] 00 53 e8 a8 2d 00 00 8b 55 e0 83 c4 14 8b ce e8 ?? c3 fc ff f7 46 18 00 00 08 00 74 2e 8b cf e8 db e5 00 00 8b f0 85 f6 74 1e 0f 1f 44 00 00 8b 16 3b d7 74 0c ff 32 8b cb e8 f1 f9 ff ff 83 c4 04 8b 76 0c 85 f6 75 e7 8b 75 e8 ff 75 f8 8b d7 8b cb e8 d8 f9 ff ff 83 c4 04 }
     // Sequence on the insertion of the db
      $seq_createdb = { 8a 43 42 84 c0 78 05 0f be c0 eb 07 8b cf e8 ?? 91 fb ff 8b 4d f8 8b d0 e8 ?? 90 fb ff 68 [3] 00 8b d6 8b cb e8 4d fc ff ff 8b f8 83 c4 04 85 ff 0f 85 41 01 00 00 68 [3] 00 8b d6 8b cb e8 32 fc ff ff 8b f8 83 c4 04 85 ff 0f 85 26 01 00 00 68 [3] 00 8b d6 8b cb e8 17 fc ff ff 8b f8 83 c4 04 85 ff 0f 85 0b 01 00 00 68 [3] 00 8b d6 8b cb e8 fc fb ff ff 8b f8 83 c4 04 85 ff 0f 85 f0 00 00 00 68 [3] 00 8b d6 8b cb e8 e1 fb ff ff 8b f8 83 c4 04 85 ff 0f 85 d5 00 00 00 68 [3] 00 8b d6 8b cb e8 c6 fb ff ff 8b f8 83 c4 04 85 ff 0f 85 ba 00 00 00 68 [3] 00 8b d6 8b cb e8 eb fa ff ff 8b f8 83 c4 04 85 ff 0f 85 9f 00 00 00 33 f6 0f 1f 40 00 0f 1f 84 00 00 00 00 00 }
     // Sequences on the drop and execution of the file
      $OP_Files1 = { 51 68 [3] 00 b9 [3] 00 e8 [2] 00 00 80 3d [3] 00 00 75 04 33 c9 eb 11 b9 [3] 00 8d 51 01 8a 01 41 84 c0 75 f9 2b ca 51 68 [3] 00 b9 [3] 00 e8 [2] 00 00 6a ?? 68 [3] 00 b9 [3] 00 e8 [2] 00 00 6a ?? 68 [3] 00 b9 [3] 00 e8 [2] 00 00 }
      $OP_Files2 = { 00 00 83 c4 04 83 78 18 10 72 05 8b 40 04 eb 03 83 c0 04 [3-9] 00 50 68 [3] 00 6a 00 6a 00 ff [1-5] 8b 95 c8 fe ff ff 83 fa 10 72 0c 8b 8d b4 fe ff ff }
      $s1 = "D$t9D$ }J" fullword ascii
      $s2 = "u#h`KN" fullword ascii
      $s3 = { 6f 73 5f 77 69 6e 2e 63 3a 25 64 3a 20 28 25 6c 75 29 20 25 73 28 25 73 29 20 2d 20 25 73 } // os_win.c:%d: (%lu) %s(%s) - %s
      $s4 = { 61 63 63 65 73 73 20 74 6f 20 25 73 2e 25 73 2e 25 73 20 69 73 20 70 72 6f 68 69 62 69 74 65 64 } // access to %s.%s.%s is prohibited
      $s5 = { 25 00 6c 00 73 00 28 00 25 00 64 00 29 } // %ls(%d) : %ls
      $s6 = { 23 46 69 6c 65 20 45 72 72 6f 72 23 28 25 64 29 20 3a } // #File Error#(%d) : 
   condition:
      uint16(0) == 0x5a4d and filesize > 600KB and 3 of ($s*) and $seq_db and $seq_createdb and all of ($OP_Files*)
}
