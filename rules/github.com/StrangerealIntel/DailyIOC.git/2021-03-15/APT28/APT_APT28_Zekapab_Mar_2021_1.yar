rule APT_APT28_Zekapab_Mar_2021_1 {
   meta:
      description = "Detect Zekapab used by APT28 group"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/DrunkBinary/status/1371423755608719360"
      date = "2021-03-15"
      hash1 = "eae62bb4110bcd00e9d1bcaba9000defcda3d1ab832fa2634d928559d066cb15"
   strings:
      $s1 = { 68 74 74 70 3A 2F 2F } // http://
      $s2 = { 68 74 74 70 73 3A 2F 2F } // https:// -> if one day in ssl version -> bonus
      $s3 = { 32 44 34 46 37 30 36 35 36 45 32 30 37 30 37 32 36 46 36 33 36 35 37 33 37 33 32 44 } // 2D4F70656E2070726F636573732D -> -Open process-
      $s4 = { 35 30 34 33 32 30 34 45 36 31 36 44 36 35 33 41 32 30 } // 5043204E616D653A20 -> PC Name:
      $s5 = { 34 42 34 32 37 32 36 34 32 30 34 43 36 31 36 45 36 37 33 41 32 30 } // 4C616E673A20 -> Lang:
      $s6 = { 53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 73 5c 25 2e 38 78 }  // System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x
      $header1 = { 2d 2d 25 73 0d 0a 43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 25 73 22 } // --%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n
      $header2 = { 2d 2d 25 73 0d 0a 43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 25 73 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 25 73 22 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 25 73 } // --%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: %s\r\n\r\n
      $dbg1 =  { 46 00 69 00 6c 00 65 00 20 00 22 00 25 00 73 00 22 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 0d 00 4e 00 6f 00 74 00 20 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 } // File "%s" not found\rNot Connected
      $dbg2 =  { 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 45 00 72 00 72 00 6f 00 72 00 2e 00 20 00 20 00 43 00 6f 00 64 00 65 00 3a 00 20 00 25 00 64 00 2e 00 0d 00 0a 00 25 00 73 } // System Error.  Code: %d.\r\n%s
      $dbg3 =  { 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 25 00 73 00 2e 00 0a 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 2e } // Connecting to %s.\nConnected.
      $dbg4 =  { 45 00 72 00 72 00 6f 00 72 00 20 00 72 00 65 00 61 00 64 00 69 00 6e 00 67 00 20 00 25 00 73 00 25 00 73 00 25 00 73 00 3a 00 20 00 25 00 73 } // Error reading %s%s%s: %s
      $dbg5 =  { 52 00 65 00 73 00 6f 00 6c 00 76 00 69 00 6e 00 67 00 20 00 68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 20 00 25 00 73 00 2e } // Resolving hostname %s.
      $dbg6 =  { 53 00 6f 00 63 00 6b 00 65 00 74 00 20 00 45 00 72 00 72 00 6f 00 72 00 20 00 23 00 20 00 25 00 64 00 0d 00 0a 00 25 00 73 } // Socket Error # %d\r\n%s
   condition:
      uint16(0) == 0x5a4d and filesize > 100KB and  1 of ($header*) and 3 of ($s*) and 4 of ($dbg*)
}
