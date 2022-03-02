rule MAL_KPot_Oct_2020_1 {
   meta:
      description = "Detect KPot stealer (new variant October 2020)"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-10-17"
      hash1 = "028ec268176707aadc2cf8e65a28236cbed214f9fd65fc3346ee34e859e50057"
   strings:
      // common KPot strings between versions
      $olds1 = "%s | %s | %s | %s | %s | %s | %s | %d | %s" fullword ascii
      $olds2 = "%s\\%s\\%s\\%.6s_%d.dat" fullword wide
      $olds3 = "%s\\%s\\%s-Qt" fullword wide
      $olds4 = "%s\\%s\\%.6ss" fullword wide
      $olds5 = "%s\\%s\\%s.vdf" fullword wide
      $olds6 = "https://%S/a/%S" fullword wide
      $olds7 = { 4e 00 61 00 6d 00 65 00 3a 00 09 00 25 00 6c 00 73 00 0d 00 0a 00 43 00 6f 00 6d 00 6d 00 65 00 6e 00 74 00 3a 00 20 00 25 00 6c 00 73 00 0d 00 0a 00 55 00 73 00 65 00 72 00 3a 00 09 00 25 00 6c 00 73 00 0d 00 0a 00 44 00 61 00 74 00 61 00 3a 00 20 00 0d 00 0a 00 00 00 00 00 25 00 32 00 2e 00 32 00 58 00 20 00 00 00 00 00 25 00 2d 00 35 00 30 00 73 00 20 00 25 00 73 }
      // new struct of data (debug)
      $debug1 = "4|Remote Desktop|%s|%s|%s|" fullword ascii
      $debug2 = "1|TotalCommander|%s|%s|%s|" fullword ascii
      $debug3 = "1|FileZilla|%s:%s|%s|%S|" fullword ascii
      $debug4 = "5|Windows Mail|%s|%s|%s|" fullword ascii
      $debug5 = "5|Outlook|%s:%d|%s|%s|" fullword ascii
      $debug6 = "1|WS_FTP|%s|%s|%S|" fullword ascii
      $debug7= "1|WinSCP|%s|%s|%s|" fullword ascii
      $debug8 = "3|Pidgin|%s|%s|%s|" fullword ascii
      $debug9 = "3|Psi(+)|%s|%s|%s|" fullword ascii
      $debug10 = "2|EarthVPN||%s|%s|" fullword ascii
      $debug11 = "2|NordVPN||%s|%s|" fullword ascii
      $debug12 = "0|%s|%S|%s|%s|%s" fullword ascii
      $debug13 = "0|%S|%s|%s|%s|%S" fullword ascii
      $debug14 = "0|%s|%s|%s|%s|" fullword ascii
      $debug15 = "Masked|%s|%02d/%04d|%s|%s|%s" fullword ascii
      // op code
      $op1 = "{53F49750-6209-4FBF-9CA8-7A333C87D1ED}_is1" fullword ascii
      $op2 = { 25 73 0d 0a 25 73 0d 0a 56 69 73 69 74 73 20 63 6f 75 6e 74 3a 20 25 64 0d 0a 4c 61 73 74 20 76 69 73 69 74 3a 20 5b 25 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 0d 0a 0d 0a 00 42 72 6f 77 73 65 72 73 5c 48 69 73 74 6f 72 79 5c 25 73 2e 74 78 74 00 42 72 6f 77 73 65 72 73 5c 41 75 74 6f 66 69 6c 6c 5c 25 73 2e 74 78 74 00 00 00 00 42 72 6f 77 73 65 72 73 5c 43 6f 6f 6b 69 65 73 5c 25 73 2e 74 78 74 }
      $op3 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" fullword ascii
      $op4 = "monero-project" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 120KB and 4 of ($olds*) and 10 of ($debug*) and 2 of ($op*)
}
