rule Ran_RegretLocker_Oct_2020_1 {
   meta:
      description = "Detect RegretLocker ransomware"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/VK_Intel/status/1323693700371914753"
      date = "2020-11-04"
      hash1 = "a188e147ba147455ce5e3a6eb8ac1a46bdd58588de7af53d4ad542c6986491f4"
   strings:
      // Sequence Open-Attach-request Disk
      $seq1 = { b8 05 dd 44 00 e8 07 7d 00 00 81 ec b0 06 00 00 53 56 33 db c7 45 cc 07 00 00 00 33 c0 89 5d c8 57 66 89 45 b8 40 c7 85 7c ff ff ff 02 00 00 00 c7 45 e0 ec 4a 98 ec 8d 75 e0 c7 45 e4 f9 a0 e9 47 8d 7d 80 c7 45 e8 90 1f 71 41 c7 45 ec 5a 66 34 5b 89 45 90 89 45 b0 89 45 b4 8d 45 d0 50 a5 8d 45 b0 50 53 68 00 00 3f 00 ff 75 0c a5 8d 85 7c ff ff ff 50 89 5d fc a5 a5 e8 76 50 00 00 85 c0 74 32 ff 15 74 00 45 00 50 68 88 1b 45 00 e8 ab de ff ff 8b 75 08 8d 45 b8 59 59 88 5d f0 8b ce ff 75 f0 89 5e 10 50 89 5e 14 e8 bb 50 ff ff e9 cb 01 00 00 53 8d 45 90 50 53 6a 04 53 ff 75 d0 e8 35 50 00 00 85 c0 74 08 50 68 bc 1b 45 00 eb bd 33 c0 8d bd 4c fb ff ff b9 82 00 00 00 be 04 01 00 00 f3 ab 8d 85 4c fb ff ff 89 75 d4 50 8d 45 d4 83 cb ff 50 ff 75 d0 e8 02 50 00 00 83 65 e8 00 8d 4d d8 33 c0 6a 07 5f 66 89 45 d8 8d 85 4c fb ff ff 50 89 7d ec e8 c6 6d ff ff 6a ff 68 f4 1b 45 00 8d 4d d8 c6 45 fc 01 e8 fd e8 ff ff 83 f8 ff 74 38 83 65 a8 00 33 c9 6a ff 50 8d 45 d8 66 89 4d 98 50 8d 4d 98 89 7d ac e8 3d df ff ff 83 7d ac 08 8d 45 98 0f 43 45 98 50 e8 bc 58 02 00 59 8d 4d 98 8b d8 e8 dd 69 ff ff 56 8d 85 54 fd ff ff 50 ff 15 f0 00 45 00 8b f8 8d 85 54 fd ff ff 50 8d 4d d8 e8 57 6d ff ff 8b 4d ec 8d 45 d8 8b 55 d8 83 f9 08 8b 75 e8 0f 43 c2 66 83 7c 70 fe 5c 75 16 83 f9 08 8d 45 d8 0f 43 c2 33 c9 66 89 4c 70 fe 8b 4d ec 8b 55 d8 83 f9 08 8d 45 d8 0f 43 c2 33 c9 51 51 6a 03 51 6a 03 51 50 ff 15 dc 00 45 00 8b f0 83 fe ff 74 7e 33 c9 8d 45 d4 51 50 68 04 01 00 00 8d 85 5c ff ff ff 50 51 51 68 00 00 56 00 56 ff 15 84 01 45 00 39 9d 64 ff ff ff 75 2c 8d 45 d4 50 68 04 01 00 00 8d 85 44 f9 ff ff 50 8d 85 54 fd ff ff 50 ff 15 08 01 45 00 8d 85 44 f9 ff ff 50 8d 4d b8 e8 b1 6c ff ff 56 ff 15 a8 00 45 00 68 04 01 00 00 8d 85 54 fd ff ff 50 57 ff 15 f8 00 45 00 85 c0 0f 85 29 ff ff ff 57 ff 15 fc 00 45 00 8b 75 08 33 c0 88 45 f0 8b ce ff 75 f0 89 46 10 89 46 14 8d 45 b8 50 e8 f3 4e ff ff 8d 4d d8 e8 cb 68 ff ff 8d 4d b8 e8 c3 68 ff ff 8b 4d f4 8b c6 5f 5e 5b 64 89 0d 00 00 00 00 c9 }
      // Sequence SMB scan
      $seq2 = { 89 7d e4 e8 d5 a9 ff ff c7 04 24 88 02 00 00 6a 40 ff 15 28 01 45 00 8b f0 c7 45 d4 88 02 00 00 8d 45 d4 89 75 e8 50 56 e8 78 1b 00 00 83 f8 6f 75 17 56 ff 15 2c 01 45 00 ff 75 d4 6a 40 ff 15 28 01 45 00 8b f0 89 45 e8 8d 45 d4 50 56 e8 52 1b 00 00 85 c0 0f 84 }
      $com1 = "bcdedit.exe / set{ default } bootstatuspolicy ignoreallfailures" fullword ascii
      $com2 = { 63 6d 64 2e 65 78 65 00 20 26 20 00 2f 43 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 31 20 2d 77 20 33 30 30 30 20 3e 20 4e 75 6c 20 26 20 44 65 6c 20 2f 66 20 2f 71 20 22 25 73 22 } // cmd.exe & /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"
      $com3 = "bcdedit.exe / set{ default } recoveryenabled No" fullword ascii
      $com4 = "vssadmin.exe Delete Shadows / All / Quiet" fullword ascii
      $com5 = "schtasks /Create /SC MINUTE /TN " fullword ascii
      $com6 = "schtasks /Delete /TN " fullword ascii
      $str1 = { 47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 30 0d 0a 48 6f 73 74 3a 20 25 73 } // GET %s HTTP/1.0\r\nHost: %s 
      $str2 = { 50 4f 53 54 20 25 73 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 25 73 } // POST %s HTTP/1.1\r\nHost: %s
      $str3 = "Content-Type: application/x-www-form-urlencoded" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 200KB and all of ($seq*) and 4 of ($com*) and 2 of ($str*)
}
