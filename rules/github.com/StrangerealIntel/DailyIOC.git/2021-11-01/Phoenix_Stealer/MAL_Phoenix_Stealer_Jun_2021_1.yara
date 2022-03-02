rule MAL_Phoenix_Stealer_Jun_2021_1 {
     meta:
          description = "Detect the Phoenix Stealer"
          author = "Arkbird_SOLG"
          reference = "https://twitter.com/3xp0rtblog/status/1455111070566207493/"
          date = "2021-11-01"
          hash1 = "5bbfeee67b9b087ed228eccdacd4a7e71d40f7f96ad869903e02d9c3b02adbe5" 
          hash2 = "34f78f4028c51f6340c1f4846b65252fa6686ba0a5ab8ebc35c737a8960ba43e" 
          hash3 = "e51de8c43034fafaa49f81e9cc955c0cf60dc9684f28d8c355baf0724710de1f" 
          tlp = "White"
          adversary = "-"
     strings: 
          $s1 = { 6a 16 58 0f be c8 88 85 b0 fe ff ff c7 85 d8 fe ff ff 42 73 7a 73 c7 85 dc fe ff ff 71 64 77 7b c7 85 e0 fe ff ff 38 73 6e 73 c6 85 e4 fe ff ff 00 e8 aa 73 ff ff 89 85 94 }
          $s2 = "UPDATE sqlite_temp_master SET sql = sqlite_rename_trigger(sql, %Q), tbl_name = %Q WHERE %s" ascii
          $s3 = { b8 c9 11 47 00 e8 c3 c5 01 00 68 f8 d7 47 00 33 db 53 53 ff 15 cc 20 47 00 53 50 89 85 d0 fc ff ff ff 15 d0 20 47 00 85 c0 0f 85 92 02 00 00 6a 01 ff 15 8c 22 47 00 84 c0 79 f4 53 e8 e2 aa 00 00 50 e8 1e 98 00 00 8b 35 84 22 47 00 8d 85 ec fe ff ff 59 59 50 53 53 6a 1c 53 ff d6 8d 8d ec fe ff ff 8d 51 01 8a 01 41 84 c0 75 f9 2b ca 8d 85 ec fe ff ff 51 50 b9 f0 5b 48 00 e8 bf 0e 00 00 8d 85 e8 fd ff ff 50 68 04 01 00 00 ff 15 40 20 47 00 8d 8d e8 fd ff ff 8d 51 01 8a 01 41 84 c0 75 f9 2b ca 8d 85 e8 fd ff ff 51 50 b9 08 5c 48 00 e8 89 0e 00 00 8d 85 e4 fc ff ff 50 53 53 6a 1a 53 ff d6 8d 8d e4 fc ff ff 8d 51 01 8a 01 41 84 c0 75 f9 2b ca 8d 85 e4 fc ff ff 51 50 b9 90 5b 48 00 e8 57 0e 00 00 8b fb 89 9d dc fc ff ff 8b f3 89 bd d4 fc ff ff 89 b5 d8 fc ff ff 83 65 fc 00 33 c9 6a 16 5a 41 e8 71 05 ff ff 8b cf 89 85 e0 fc }
          $s4 = { 6a 01 ff 15 98 22 47 00 85 c0 74 5d 6a 00 ff 15 a0 22 47 00 85 c0 74 51 56 6a 01 ff 15 94 22 47 00 8b f0 85 f6 74 3b 56 ff 15 38 21 47 00 8b d0 85 d2 74 27 8b ca 57 8d 79 01 8a 01 41 84 c0 75 f9 2b cf 6a 03 51 8b 0d 6c 72 48 00 52 ba 58 d7 47 00 e8 95 1b fe ff 83 c4 0c 5f 56 ff 15 64 21 47 00 }
          $s5 = { 81 ec 14 02 00 00 a1 0c 50 48 00 33 c5 89 45 fc 53 56 8b d9 be 19 27 00 00 57 8b 7d 0c 83 fb ff 75 0c e8 bb eb ff ff 89 37 89 47 04 eb 17 ff 75 08 52 53 ff 15 bc 22 47 00 85 c0 8b cf 0f 95 c2 e8 b8 fe ff ff e8 98 eb ff ff 8b 4f 04 8b 49 04 3b 48 04 75 08 81 3f 34 27 00 00 74 20 e8 80 eb ff ff 8b 4f 04 8b 49 04 3b 48 04 0f 85 b9 00 00 00 81 3f 33 27 00 00 0f 85 ad 00 00 00 83 fb ff 75 0c e8 5b eb ff ff 89 37 e9 99 00 00 00 33 c0 89 9d f8 fd ff ff 40 89 9d fc fe ff ff 89 85 f4 fd ff ff 89 85 f8 fe ff ff 8d 85 f8 fe ff ff 6a 00 50 8d 85 f4 fd ff ff 50 6a 00 8d 43 01 50 ff 15 d8 22 47 00 8b f0 8b cf 85 f6 0f 98 c2 e8 2a fe ff ff 85 f6 78 53 83 a5 f0 fd ff ff 00 8d 85 ec fd ff ff 50 8d 85 f0 fd ff ff c7 85 ec fd ff ff 04 00 00 00 50 68 07 10 00 00 68 ff ff 00 00 53 ff 15 b0 22 47 00 8b f0 8b cf 85 f6 0f 95 c2 e8 e8 fd ff }
    condition:
          uint16(0) == 0x5a4d and filesize > 80KB and 4 of ($s*)
}
