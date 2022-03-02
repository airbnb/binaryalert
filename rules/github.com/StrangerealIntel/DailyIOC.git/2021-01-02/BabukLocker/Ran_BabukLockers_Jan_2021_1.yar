rule Ran_BabukLockers_Jan_2021_1 {
   meta:
      description = "Detect the BabukLocker ransomware"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-01-03"
      hash1 = "8203c2f00ecd3ae960cb3247a7d7bfb35e55c38939607c85dbdb5c92f0495fa9"
      level = "Experimental"
   strings:
      // sequence of the discovery process from imported DLL (TTPs)
      $seq1 = { 55 8b ec 83 ec 14 a1 b0 81 40 00 33 c5 89 45 fc c7 45 f8 ff ff ff ff c7 45 f4 00 40 00 00 8d 45 f0 50 8b 4d 08 51 6a 13 6a 00 6a 02 e8 85 2b 00 00 85 c0 0f 85 a3 00 00 00 8b 55 f4 52 e8 ae 06 00 00 83 c4 04 89 45 08 83 7d 08 00 0f 84 81 00 00 00 8d 45 f4 50 8b 4d 08 51 8d 55 f8 52 8b 45 f0 50 e8 55 2b 00 00 85 c0 75 5c c7 45 ec 00 00 00 00 eb 09 8b 4d ec 83 c1 01 89 4d ec 8b 55 ec 3b 55 f8 73 40 8b 45 ec c1 e0 05 8b 4d 08 8b 54 01 0c 83 e2 02 74 14 8b 45 ec c1 e0 05 03 45  }         
      // sequence of the parsing arguments + shutdown process
      $seq2 = { 68 68 22 40 00 b8 04 00 00 00 c1 e0 00 8b 8d 9c fd ff ff 8b 14 01 52 ff 15 b8 90 40 00 85 c0 75 0c c7 85 b0 fd ff ff 01 00 00 00 eb 58 68 74 22 40 00 b8 04 00 00 00 c1 e0 00 8b 8d 9c fd ff ff 8b 14 01 52 ff 15 b8 90 40 00 85 c0 75 0c c7 85 b0 fd ff ff 00 00 00 00 eb 2b 68 80 22 40 00 b8 04 00 00 00 c1 e0 00 8b 8d 9c fd ff ff 8b 14 01 52 ff 15 b8 90 40 00 85 c0 75 0a c7 85 b0 fd ff ff ff ff ff ff e9 55 ff ff ff 6a 00 6a 00 ff 15 a8 90 40 00 e8 aa 04 00 00 e8 05 }
      // sequence of write op (key) in the disk
      $seq3 = { 83 c4 0c 68 f4 00 00 00 8d 85 f4 fd ff ff 50 68 88 22 40 00 ff 15 6c 90 40 00 68 98 22 40 00 8d 8d f4 fd ff ff 51 ff 15 c4 90 40 00 c7 85 ec fd ff ff 00 00 00 00 6a 00 68 80 00 00 00 6a 01 6a 00 6a 01 68 00 00 00 40 8d 95 f4 fd ff ff 52 ff 15 70 90 40 00 89 85 98 fd ff ff 83 bd 98 fd ff ff ff 0f 84 2e 03 00 00 6a 00 8d 85 ec fd ff ff 50 68 90 00 00 00 68 78 82 40 00 8b 8d 98 fd ff ff 51 ff 15 90 90 }
      $s1 = "\\ecdh_pub_k.bin" fullword wide 
      $s2 = "ntuser.dat.log" fullword wide 
      $s3 = "cmd.exe" fullword ascii
      $s4 = "/c vssadmin.exe delete shadows /all /quiet" fullword wide 
      $s5 = { 5c 00 5c 00 3f 00 5c 00 00 00 00 00 3a 00 00 00 98 2f } 
   condition:
      uint16(0) == 0x5a4d and filesize > 15KB and 2 of ($seq*) and 3 of ($s*) 
}
