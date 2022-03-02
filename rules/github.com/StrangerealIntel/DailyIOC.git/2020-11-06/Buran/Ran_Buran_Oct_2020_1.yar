rule Ran_Buran_Oct_2020_1 {
   meta:
      description = "Detect Buran ransomware"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/JAMESWT_MHT/status/1323956405976600579"
      date = "2020-11-05"
      hash1 = "66fc6e71a9c6be1f604c4a2d0650914f67c45d894fd1f76913e463079d47a8af"
      hash2 = "93fe277d54f4baac5762412dda6f831bf6a612f166daade7c23f6b38feac94fb"
      hash3 = "b3302c4a9fd06d9fde96c9004141f80e0a9107a9dead1659e77351f1b1c87cf6"
      hash4 = "eb920e0fc0c360abb901e04dce172459b63bbda3ab8152350885db4b44d63ce5"
      hash5 = "f247ae6db52989c9a598c3c7fbc1ae2db54f5c65be862880e11578b8583731cb"
      hash6 = "29cdd5206422831334afa75c113b615bb8e0121254dd9a2196703ce6b1704ff8"
   strings:
      $s1 = "!!! LOCALPUBKEY !!!" fullword ascii
      $s2 = "!!! ENCLOCALPRIVKEY !!!" fullword ascii
      $s3 = "!!! D !!!" fullword ascii
      $s4 = { 8b 85 74 fd ff ff 8b 40 04 85 c0 74 05 83 e8 04 8b 00 8d 55 f4 92 e8 c1 aa fe ff 8b 85 74 fd ff ff 8b 78 04 85 ff 74 05 83 ef 04 8b 3f 8d 45 f4 e8 d3 a8 fe ff 8b d0 8b cf 8b 85 50 fd ff ff 8b 38 ff 57 0c 6a 00 6a 00 33 d2 8b 85 50 fd ff ff 8b 08 ff 51 18 8b 45 f4 8b 95 74 fd ff ff 8b 52 04 e8 da a7 fe ff 0f 84 7d 07 00 00 ff b5 4c fd ff ff ff b5 48 fd ff ff 33 d2 8b 85 50 fd ff ff 8b 08 ff 51 18 8b 85 74 fd ff ff 8b 78 04 85 ff 74 05 83 ef 04 8b 3f 8b 85 74 fd ff ff 83 c0 04 e8 63 a8 fe ff 8b d0 8b cf 8b 85 50 fd ff ff 8b 38 ff 57 10 6a 00 6a 00 33 d2 8b 85 50 fd ff ff 8b 08 ff 51 18 8b 85 74 fd ff ff 8b 78 04 85 ff 74 05 83 ef 04 8b 3f 8b 85 50 fd ff ff 8b 10 ff 12 52 50 8b c7 99 03 85 48 fd ff ff 13 95 4c fd ff ff 3b 54 24 04 75 03 3b 04 24 5a 58 0f 85 dc 06 00 00 ff b5 4c fd ff ff ff b5 48 fd ff ff 8b 85 50 fd ff ff e8 e6 cc fe ff 8b 85 74 fd ff ff 8b 40 28 85 c0 74 09 83 f8 0a 0f 85 00 01 00 00 8b 85 74 fd ff ff 83 c0 1c e8 fe a2 fe ff 8b 85 74 fd ff ff 83 c0 20 e8 f0 a2 fe ff c7 85 44 fd ff ff 01 00 00 00 b8 00 01 00 00 e8 78 44 ff ff 8b d0 8d 85 10 fd ff ff e8 b7 a4 fe ff 8b 95 10 fd ff ff 8b 85 74 fd ff ff 83 c0 20 e8 63 a5 fe ff 83 bd 44 fd ff ff 10 7f 2b b8 00 01 00 00 e8 44 44 ff ff 8b d0 8d 85 0c fd ff ff e8 83 a4 fe ff 8b 95 0c fd ff ff 8b 85 74 fd ff ff 83 c0 1c e8 2f a5 fe ff ff 85 44 fd ff ff 83 bd 44 fd ff ff 21 75 92 8b 85 74 fd ff ff 83 c0 24 50 8b 85 74 fd ff ff 8b 48 1c 8b 85 74 fd ff ff 8b 50 20 8d 85 08 fd ff ff e8 45 a5 fe ff 8b 85 08 fd ff ff 8b 95 74 fd ff ff 8d 4a 0c 8b 95 74 fd ff ff 83 c2 14 e8 c8 8f ff ff 8d 95 04 fd ff ff 8b 85 74 fd ff ff 8b 40 24 e8 0c 5c ff ff 8b 95 04 fd ff ff 8b 85 74 fd ff ff 83 c0 24 e8 60 a2 fe ff 8b 85 74 fd ff ff 83 78 28 0a 75 0d 8b 85 74 fd ff ff 33 d2 89 50 28 eb 09 8b 85 74 fd ff ff ff 40 28 8b c3 99 52 50 8b 85 48 fd ff ff 8b 95 4c fd ff ff e8 54 b2 fe ff 89 85 38 fd ff ff 89 95 3c fd ff ff 8b c3 99 52 50 8b 85 38 fd ff ff 8b 95 3c fd ff ff e8 0e b2 fe ff 52 50 8b c6 99 3b 54 24 04 75 09 3b 04 24 5a 58 73 18 eb 04 5a 58 7d 12 8b c6 99 f7 fb 99 89 85 38 fd ff ff 89 95 3c fd ff ff 83 bd 3c fd ff ff 00 75 07 83 bd 38 fd ff ff 00 74 31 ff b5 3c fd ff ff ff b5 38 fd ff ff 8b 85 48 fd ff ff 8b 95 4c fd ff ff e8 d9 b1 fe ff 89 85 30 fd ff ff 89 95 34 fd ff ff 89 9d 2c fd ff ff eb 38 c7 85 38 fd ff ff 01 00 00 00 c7 85 3c fd ff ff 00 00 00 00 8b 85 48 fd ff ff 89 85 30 fd ff ff 8b 85 4c fd ff ff 89 85 34 fd ff ff 8b 85 48 fd ff ff 89 85 2c fd ff ff 8d 45 f0 e8 05 a1 fe ff b2 01 a1 98 6f 40 00 e8 61 94 fe ff 89 85 1c fd ff ff 8b 9d 38 fd ff ff 85 db 0f 8e 9f 00 00 00 c7 85 44 fd ff ff 01 00 00 00 ff b5 34 fd ff ff ff b5 30 fd ff ff 8b 85 44 fd ff ff 48 99 e8 1e b1 fe ff 89 85 20 fd ff ff 89 95 24 fd ff ff 8d 95 20 fd ff ff b9 08 00 00 00 8b 85 1c fd ff ff 8b 30 ff 56 10 ff b5 24 fd ff ff ff b5 20 fd ff ff 33 d2 8b 85 50 fd ff ff 8b 08 ff 51 18 8d 45 f4 8b 95 2c fd ff ff e8 19 a7 fe ff 8d 45 f4 e8 3d a5 fe ff 8b d0 8b 8d 2c fd ff ff 8b 85 50 fd ff ff e8 e6 ca fe ff 8d 45 f0 8b 55 f4 e8 fb a2 fe ff ff 85 44 fd ff ff 4b 0f 85 6b ff ff ff 6a 00 6a 00 33 d2 8b 85 1c fd ff ff 8b 08 ff 51 18 8d 45 ec e8 2d a0 fe ff 8b 85 1c fd ff ff 8b 10 ff 12 89 85 18 fd ff ff 8d 45 ec 8b 95 18 fd ff ff e8 af a6 fe ff 8d 45 ec e8 d3 a4 fe ff 8b d0 8b 8d 18 fd ff ff 8b 85 1c fd ff ff 8b 18 ff 53 }
      $s5 = ": :(:,:0:4:8:<:@:D:H:\\:|:" fullword ascii
      $s6 = " remove '.' from {.$DEFINE ComplexBraces}" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 100KB and 4 of them
}
