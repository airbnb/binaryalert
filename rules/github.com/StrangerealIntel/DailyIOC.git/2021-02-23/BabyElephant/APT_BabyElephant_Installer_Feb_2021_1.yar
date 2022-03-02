rule APT_BabyElephant_Installer_Feb_2021_1 {
   meta:
      description = "Detect Installer from BabyElephant APT"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/h2jazi/status/1363683531067715584"
      date = "2021-02-23"
      level = "experimental"
      hash1 = "d55ff954abb04ec29745f7d80ea7457a862c8025a21e889f1ba44c32ba486a7e"
   strings:
      $s1 = { 65 63 68 6f 20 25 64 20 3e 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c }
      $s2 = "COMSPEC" fullword ascii 
      $s3 = { 53 43 48 54 41 53 4b 53 20 2f 43 52 45 41 54 45 20 2f 53 43 20 4d 49 4e 55 54 45 20 2f 4d 4f 20 [1-3] 20 2f 54 4e 20 22 [1-12] 22 20 2f 54 52 20 22 [4-24] 22 20 2f 66 }
      $s4 = "%s//%s" fullword ascii
      $s5 = { 53 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 54 4e 20 22 [1-12] 22 20 2f 66 } 
      // seq CMD call
      $s6 = { 83 c4 10 8b d8 e8 13 02 00 00 83 fb ff 74 06 89 38 8b f3 eb 34 83 38 02 74 0f e8 fe 01 00 00 83 38 0d 74 05 83 ce ff eb 20 e8 ef 01 00 00 89 38 56 8d 45 ec b9 c4 3e 42 00 50 51 56 89 4d ec }
      // seq shell -> c2hlbGw= (base64)
      $s7 = { 68 00 08 00 00 8d 85 48 f6 ff ff 6a 00 50 e8 00 33 00 00 83 c4 0c 8d 85 48 f6 ff ff 6a 00 68 00 08 00 00 50 53 ff d6 85 c0 0f 8e 1f 03 00 00 0f 1f 40 00 6a 08 68 e0 b3 42 00 8d 8d 28 ec ff ff c7 85 38 ec ff ff 00 00 00 00 c7 85 3c ec ff ff 0f 00 00 00 c6 85 28 ec ff ff 00 e8 a3 09 00 00 8d 95 28 ec ff ff c7 45 fc 00 00 00 00 8d 8d 10 ec ff ff e8 2b 05 00 00 83 }
   condition:
      uint16(0) == 0x5a4d and filesize > 80KB and all of them 
}
