rule  APT_APT29_MiniDuke_Mar_2021_1 {
   meta:
      description = "Detect MiniDuke implant used by APT29 group"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2021-03-08"
      hash1 = "6057b19975818ff4487ee62d5341834c53ab80a507949a52422ab37c7c46b7a1"
      level = "Experimental"
   strings:
      // ref strings
      $s1 = { 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69 70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 3b 20 62 6f 75 6e 64 61 72 79 3d 00 00 00 00 2d 2d 25 73 0d 0a 43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 25 73 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 25 73 22 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 25 73 0d 0a 43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 25 73 }
      $s2 = { 70 72 6f 63 3a 20 20 25 64 20 25 73 0a 6c 6f 67 69 6e 3a 20 25 73 5c 25 73 0a 49 44 3a 20 20 20 20 30 78 25 30 38 58 0a 68 6f 73 74 3a 20 20 25 73 3a 25 64 0a 6d 65 74 68 3a 20 20 25 73 20 25 64 0a 70 69 70 65 3a 20 5c 5c 25 73 5c 70 69 70 65 5c 25 73 0a 6c 61 6e 67 3a 20 20 25 73 0a 64 65 6c 61 79 3a 20 25 64 }
      $s3 = { 75 70 74 69 6d 65 20 25 35 64 2e 25 30 32 64 68 0a 00 25 73 3a 25 64 00 25 73 5c 25 73 00 3f 00 25 64 20 25 73 0a 25 73 20 25 73 20 25 73 }
      // seq set_app_type
      $s4 = { 55 89 e5 83 ec 14 6a 02 ff 15 b8 53 44 00 e8 fd fe ff ff 8d b6 00 00 00 00 8d bc 27 00 00 00 00 55 89 e5 83 ec 14 6a 01 ff 15 }
      // seq create the pipes
      $s5 = { 8b 85 54 64 ff ff 8b 95 44 64 ff ff 83 c2 44 89 44 24 04 89 14 24 e8 a4 e5 fc ff 83 ec 08 8b 85 44 64 ff ff 83 c0 38 c7 44 24 08 0c 00 00 00 c7 44 24 04 00 00 00 00 89 04 24 e8 8c e8 fd ff 8b 85 44 64 ff ff c7 40 38 0c 00 00 00 8b 85 44 64 ff ff c7 40 40 01 00 00 00 8b 85 44 64 ff ff c7 40 3c 00 00 00 00 8b 85 44 64 ff ff 8d 58 38 8b 85 44 64 ff ff 8d 50 1c 8b 85 44 64 ff ff 83 c0 18 c7 44 24 0c 00 40 00 00 89 5c 24 08 89 54 24 04 89 04 24 e8 2e e5 fc ff 83 ec 10 85 c0 0f 95 c0 84 c0 0f 84 09 05 00 00 8b 85 44 64 ff ff 8d 58 38 8b 85 44 64 ff ff 8d 50 24 8b 85 44 64 ff ff 83 c0 20 c7 44 24 0c 00 40 00 00 89 5c 24 08 89 54 24 04 89 04 24 e8 eb e4 fc ff 83 ec 10 85 c0 0f 95 c0 84 c0 }
   condition:
      uint16(0) == 0x5a4d and filesize > 150KB and 3 of them
}
