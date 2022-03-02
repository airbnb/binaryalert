rule APT_APT28_Downdelph_Feb_2021_1 {
   meta:
      description = "Detect Downdelph used by APT28 group"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/RedDrip7/status/1362343352759250946"
      date = "2021-02-18"
      hash1 = "ee7cfc55a49b2e9825a393a94b0baad18ef5bfced67531382e572ef8a9ecda4b"
   strings:
      // seq parse disks + getpath
      $s1 = { 53 [1-3] 81 c4 [2] ff ff 8b f2 8b ?? 54 8d 44 24 08 50 68 04 01 00 00 8b ?? e8 [12-22] 8d 54 24 04 8b c6 [73-133] 33 d2 52 50 8b 45 e8 8b 55 ec e8 [3] ff 8b 4d 0c 89 01 89 51 04 8b 45 f0 33 d2 52 50 8b 45 e8 8b 55 ec e8 [3] ff 8b 4d 10 89 01 89 51 04 8b c3 5b 8b e5 5d }
      $s2 = "cmd.exe /c " fullword ascii
      $s3 = "Failed to Save Stream %s is already associated with %s=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide
      $s4 = { 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 20 00 4c 00 61 00 79 00 6f 00 75 00 74 00 73 00 5c 00 25 00 2e 00 38 00 78 } // System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x
      $s5 = { 4a 00 50 00 45 00 47 00 20 00 65 00 72 00 72 00 6f 00 72 00 20 00 23 00 25 00 64 } // JPEG error #%d
      $s6 = { 45 00 72 00 72 00 6f 00 72 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 3a 00 20 00 25 00 73 } // Error connecting to server: %s
   condition:
      uint16(0) == 0x5a4d and filesize > 100KB and 5 of them
}
