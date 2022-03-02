rule APT_Turla_BigBoss_Apr_2021_1 {
   meta:
      description = "Detects new BigBoss implants (SilentMoon/GoldenSky)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/DrunkBinary/status/1304086230540390400"
      date = "2021-04-06"
      hash1 = "94421ccb97b784c43d92c4b1438481eee9c907db6b13f6cfc4b86a6bb057ddcd"
      hash2 = "67bfa585ace8df20deb1d8a05bd4acf2c84c6fa0966276b3ea7607056abe25bb"
      hash3 = "6ca0b4efe077fe05b2ae871bf50133c706c7090a54d2c3536a6c86ff454caa9a"
   strings:
      $s1 = { 55 8b ec a1 [2] 40 00 83 ec 3c 50 6a 3c 8d 4d c4 51 68 [2] 40 00 68 [2] 40 00 68 [2] 40 00 ff 15 78 ?? 40 00 8d 45 c4 8d 50 02 8d 49 00 66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 75 1c 8b 15 [2] 40 00 52 68 [2] 40 00 68 [2] 40 00 68 [2] 40 00 ff 15 [2] 40 00 8b e5 }
      $s2 = { 5c 00 5c 00 2e 00 5c 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 50 00 49 00 50 00 45 00 5c }
      $s3 = { 5c 5c 25 73 5c 70 69 70 65 5c 25 73 }
      $s4 = { 5c 00 69 00 6e 00 66 00 5c 00 00 00 [4-16] 2e 00 69 00 6e 00 66 }
      $s5 = "%d blocks, %d sorted, %d scanned" ascii fullword
      $s6 = "REMOTE_NS:ERROR:%d" ascii fullword     
      $s7 = { 5c 5c 25 73 5c 69 70 63 24 }
      $s8 = { 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 6c 00 61 00 6e 00 6d 00 61 00 6e 00 73 00 65 00 72 00 76 00 65 00 72 00 5c 00 70 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 73 00 00 00 4e 00 75 00 6c 00 6c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 50 00 69 00 70 00 65 00 73 00 00 00 00 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 4c 00 53 00 41 00 00 00 00 00 52 00 65 00 73 00 74 00 72 00 69 00 63 00 74 00 41 00 6e 00 6f 00 6e 00 79 00 6d 00 6f 00 75 00 73 }
   condition:
      uint16(0) == 0x5a4d and filesize > 20KB and 7 of ($s*)
}
