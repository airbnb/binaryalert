import "pe"

rule APT_APT28_VHD_Nov_2020_1 {
   meta:
      description = "Detect suspicious VHD file with APT28 artefacts inside (November 2020)"
      author = "Arkbird_SOLG"
      reference = "https://www.intezer.com/blog/research/russian-apt-uses-covid-19-lures-to-deliver-zebrocy/"
      date = "2020-12-09"
      // so few samples for confirm sequences, be careful
      level= "experimental"
      hash1 = "707b752f6bd89d4f97d08602d0546a56d27acfe00e6d5df2a2cb67c5e2eeee30"
   strings:
      // Check if is a VHD
      $c1 = { 49 6e 76 61 6c 69 64 20 70 61 72 74 69 74 69 6f 6e 20 74 61 62 6c 65 00 45 72 72 6f 72 20 6c 6f 61 64 69 6e 67 20 6f 70 65 72 61 74 69 6e 67 20 73 79 73 74 65 6d 00 4d 69 73 73 69 6e 67 20 6f 70 65 72 61 74 69 6e 67 20 73 79 73 74 65 6d 00 00 00 63 7b }
      $c2 = { 52 90 4e 54 46 53 }
      $c3 = { 41 20 64 69 73 6b 20 72 65 61 64 20 65 72 72 6f 72 20 6f 63 63 75 72 72 65 64 00 0d 0a 42 4f 4f 54 4d 47 52 20 69 73 20 63 6f 6d 70 72 65 73 73 65 64 00 0d 0a 50 72 65 73 73 20 43 74 72 6c 2b 41 6c 74 2b 44 65 6c 20 74 6f 20 72 65 73 74 61 72 74 }
      $c4 = { 42 00 4f 00 4f 00 54 00 4d 00 47 00 52 00 04 00 24 00 49 00 33 00 30 }
      $c5 = { 4e 00 54 00 4c 00 44 00 52 00 07 00 42 00 4f 00 4f 00 54 00 54 00 47 00 54 00 07 00 42 00 4f 00 4f 00 54 00 4e 00 58 00 54 }
      $c6 = { 46 49 4c 45 30 00 03 00 8? ?d }
      $c7 = { 24 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 60 00 00 00 40 }
      // check artefacts used by APT28
      $s1 = { 46 61 73 74 4d 4d 20 42 6f 72 6c 61 6e 64 20 45 64 69 74 69 6f 6e 20 a9 20 32 30 30 34 2c 20 32 30 30 35 20 50 69 65 72 72 65 20 6c 65 20 52 69 63 68 65 20 2f 20 50 72 6f 66 65 73 73 69 6f 6e 61 6c 20 53 6f 66 74 77 61 72 65 20 44 65 76 65 6c 6f 70 6d 65 6e 74 }
      $s2 = { 53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c 00 46 50 55 4d 61 73 6b 56 61 6c 75 65 }
      $s3 = { 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 73 5c }
      $s4 = { 53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 73 5c 25 2e 38 78 00 00 6c 61 79 6f 75 74 20 74 65 78 74 }
      $s5 = { 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 25 00 73 }
      $s6 = { 52 00 65 00 73 00 6f 00 6c 00 76 00 69 00 6e 00 67 00 20 00 68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 20 00 25 00 73 }
      $s7 = { 45 00 72 00 72 00 6f 00 72 00 20 00 72 00 65 00 61 00 64 00 69 00 6e 00 67 00 20 00 25 00 73 00 25 00 73 00 25 00 73 00 3a 00 20 00 25 00 73 00 11 00 53 00 74 00 72 00 65 00 61 00 6d 00 20 00 72 00 65 00 61 00 64 00 20 00 65 00 72 00 72 00 6f 00 72 }
      $s8 = { 25 73 2c 20 43 6c 61 73 73 49 44 3a 20 25 73 }
      $s9 = { 43 6f 6e 6e 65 63 74 4b 69 6e 64 b0 10 40 00 44 00 00 ff 44 00 00 ff 01 00 00 00 00 00 00 80 00 00 00 80 04 00 11 52 65 6d 6f 74 65 4d 61 63 68 69 6e 65 4e 61 6d 65 }
      $s10 = { 22 20 4e 54 2f 20 [1-4] 20 4f 4d 2f 20 45 54 55 4e 49 4d 20 43 53 2f 20 65 74 61 65 72 43 2f 20 73 6b 73 61 74 68 63 73 }
      $s11 = { 2f 2f 3a 70 74 74 68 }
   condition:
      uint16(0) == 0x33c0 and filesize > 40KB and 5 of ($c*) and 8 of ($s*)
}

rule APT_APT28_Zebrocy_GO_Downloader_Nov_2020_1 {
   meta:
      description = "Detect Zebrocy Go downloader (November 2020)"
      author = "Arkbird_SOLG"
      reference = "https://www.intezer.com/blog/research/russian-apt-uses-covid-19-lures-to-deliver-zebrocy/"
      date = "2020-12-09"
      // so few samples for confirm impshash and sequences, be careful
      level= "experimental"
      hash1 = "61c2e524dcc25a59d7f2fe7eff269865a3ed14d6b40e4fea33b3cd3f58c14f19"
      hash2 = "f36a0ee7f4ec23765bb28fbfa734e402042278864e246a54b8c4db6f58275662"
   strings:
      $c1 = "os.(*ProcessState).sys" fullword ascii
      $c2 = "os/exec.(*ExitError).Sys" fullword ascii
      $c3 = "os/exec.ExitError.Sys" fullword ascii
      $c4 = "os.(*ProcessState).Sys" fullword ascii
      $p1 = "syscall.CreatePipe" fullword ascii 
      $p2 = "os.Pipe" fullword ascii
      $p3 = { 6e 65 74 2f 68 74 74 70 2e 28 2a 68 74 74 70 32 70 69 70 65 29 2e 63 6c 6f 73 65 44 6f 6e 65 4c 6f 63 6b 65 64 }
      $p4 = { 6e 65 74 2f 68 74 74 70 2e 28 2a 68 74 74 70 32 63 6c 69 65 6e 74 53 74 72 65 61 6d 29 2e 67 65 74 53 74 61 72 74 65 64 57 72 69 74 65 }
      $op1 = { 75 5f 67 3d 25 73 20 25 71 25 73 2a 25 64 25 73 3d 25 73 26 23 33 34 3b 26 23 33 39 3b 26 61 6d 70 3b }
      $op2 = { 70 63 3d 25 21 28 4e 4f 56 45 52 42 29 25 21 57 65 65 6b 64 61 79 28 25 73 7c 25 73 25 73 7c 25 73 28 42 41 44 49 4e 44 45 58 29 }
      $op3 = { 48 54 54 50 5f 50 52 4f 58 59 48 6f 73 74 3a 20 25 73 0d 0a 49 50 20 61 64 64 72 65 73 73 4b 65 65 70 2d 41 6c 69 76 65 }
      $op4 = { 63 6f 6e 6e 65 63 74 69 6f 6e 20 65 72 72 6f 72 3a 20 25 73 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 69 6d 65 64 20 6f 75 74 }
      // Bonus RSA key
      $op5 = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 54 45 53 54 49 4e 47 20 4b 45 59 2d 2d 2d 2d 2d }
      $op6 = { 2d 2d 2d 2d 2d 45 4e 44 20 52 53 41 20 54 45 53 54 49 4e 47 20 4b 45 59 2d 2d 2d 2d 2d }
   condition:
      uint16(0) == 0x4d5a and filesize > 800KB and (pe.imphash() == "91802a615b3a5c4bcc05bc5f66a5b219") and 3 of ($c*) and 3 of ($p*) and 3 of ($op*)
}
