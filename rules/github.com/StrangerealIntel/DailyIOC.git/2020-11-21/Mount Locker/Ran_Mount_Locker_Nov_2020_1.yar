rule Ran_Mount_Locker_Nov_2020_1 {
   meta:
      description = "Detect Mount Locker ransomware (November 2020 variant)"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-11-20"
      hash1 = "e7c277aae66085f1e0c4789fe51cac50e3ea86d79c8a242ffc066ed0b0548037"
      hash2 = "226a723ffb4a91d9950a8b266167c5b354ab0db1dc225578494917fe53867ef2"
   strings:
      $s1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword wide
      $s2 = "VBA6.DLL" fullword ascii
      $s3 = "MSComDlg.CommonDialog" fullword ascii
      $s4 = "DllFunctionCall" fullword ascii 
      $s5 = { 00 2a 00 5c 00 41 00 43 00 3a 00 5c [35-160] 00 2e 00 76 00 62 00 70 } // check vbp path existance
      $s6 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\COMCTL32.oca" fullword wide
      $s7 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\MSFLXGRD.oca" fullword ascii 
      $s8 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s9 = "SFLXGRD.OCX" fullword ascii
      $s10 = "COMDLG32.OCX" fullword ascii
      $s11 = "COMCTL32.OCX" fullword ascii
      // Seq on algorithms
      $seq1 = { 42 00 24 00 40 00 43 00 67 00 2f 00 44 00 08 00 4a 00 51 00 77 00 54 00 76 00 25 00 55 00 48 00 00 00 00 00 5d 00 4c 00 09 00 53 00 3e 00 73 00 62 00 52 00 50 00 0b 00 61 00 01 00 61 01 3a 00 03 00 57 00 4f 00 75 00 54 00 71 00 22 00 53 00 37 00 00 00 30 00 1d 00 46 00 5a 00 5c 00 48 00 78 00 63 00 02 00 1d 00 23 00 3b 00 28 00 55 00 73 00 28 00 61 00 3b 00 00 00 00 00 44 00 4e 00 4a 00 4d 00 61 00 40 00 59 00 2b 00 38 00 02 01 04 01 54 00 08 00 52 00 56 00 1d 00 42 00 3e 00 00 00 00 00 35 00 70 00 3b 00 37 00 6f 00 26 00 26 00 40 00 64 00 02 00 51 00 3c 00 41 00 16 00 3e 00 00 00 47 00 58 00 33 00 89 00 54 00 2d 00 29 00 50 00 04 00 59 00 5d 00 4f 00 1b 00 36 00 30 00 83 00 41 00 00 00 2a 00 54 00 47 00 86 00 56 00 19 00 24 00 4e 00 3a 00 45 00 51 00 4d 00 1e 00 3b 00 2b 00 81 00 35 00 00 00 3a 00 65 00 57 00 03 00 2d 00 62 00 53 }
      $seq2 = { 5a 00 3d 00 14 00 51 00 1f 00 67 00 1c 00 24 00 00 00 00 00 00 00 6f 00 27 00 62 00 5d 00 6d 00 30 00 01 00 27 01 25 00 62 00 7b 00 05 00 56 00 24 00 3c 00 3d 00 5d 00 2e 00 62 00 03 00 0a 00 57 00 6a 00 02 00 5d 00 02 01 23 01 67 00 20 00 54 00 01 00 6c 01 17 00 0b 00 44 00 21 00 1e 00 01 00 52 01 60 00 3b 00 11 00 45 00 2a 00 59 00 2c 00 19 00 00 00 5a 00 1e 00 61 00 5c 00 6b 00 31 00 01 00 1a 01 2d 00 4a 00 6f 00 11 00 57 00 2c 00 3a 00 3a 00 50 00 2a 00 61 00 02 00 07 00 53 00 7b 00 01 01 5b 00 02 01 6a 01 0b 00 03 00 6d 00 43 00 0c 00 64 00 4d 00 44 00 5f 00 08 00 5a 00 68 00 2b 00 32 00 68 }
   condition:
      uint16(0) == 0x5a4d and filesize > 100KB and 6 of ($s*) and 1 of ($seq*)
}
