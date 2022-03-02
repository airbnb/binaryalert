rule Ran_Ruyk_Oct_2020_2 {
   meta:
      description = "Detect RYUK ransomware (Sept_2020_V1 + V2)"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-10-25"
      hash1 = "d0d7a8f588693b7cc967fb4069419125625eb7454ba553c0416f35fc95307cbe"
      hash2 = "d7333223dcc1002aae04e25e31d8c297efa791a2c1e609d67ac6d9af338efbe8"
      hash3 = "bbbf38de4f40754f235441a8e6a4c8bdb9365dab7f5cfcdac77dbb4d6236360b"
      hash4 = "cfe1678a7f2b949966d9a020faafb46662584f8a6ac4b72583a21fa858f2a2e8"
      hash5 = "e8a0e80dfc520bf7e76c33a90ed6d286e8729e9defe6bb7da2f38bc2db33f399"
      hash6 = "5b1f242aee0eabd4dffea0fe5f08aba60abf7c8d1e4f7fc7357af7f20ccd0204"
   strings:
      $s1 = "Type Descriptor'" fullword ascii
      $s2 = "Class Hierarchy Descriptor'" fullword ascii
      $s3 = "GET:PV" fullword ascii
      $s4 = "Base Class Descriptor at (" fullword ascii
      $s5 = "Complete Object Locator'" fullword ascii
      $s6 = "UINi\\cYIqwxAcV^GYCY^EgzUvSZcsRW" fullword ascii
      $s7 = "FrystFsgcteIaui" fullword ascii
      $s8 = "delete[]" fullword ascii
      $s9 = "Picuovphv Bbsg!Es|rwojrarkkd Stryjfes x4.3" fullword ascii
      $s10 = "FrystGfuvrozHctj" fullword ascii
      $s11 = "FrystUfngasfCqovf{v" fullword ascii
      $op1 = { 63 62 6d 75 6a 7a 6e 49 4d 54 50 78 75 70 78 59 6f 65 71 4f 57 48 4a 78 57 71 4c 50 55 78 4a 6e 68 4b 71 57 57 6d 49 75 6a 51 64 4f 50 74 70 63 76 61 42 72 75 5a 6a 4d 69 79 59 52 69 58 78 4a 63 6b 51 70 4b 75 47 52 5a 51 42 5a 5a 61 50 69 76 66 77 43 6c 45 5a 67 76 6e 49 6c 54 74 4b 46 4d 68 53 4a 42 4f 64 6a 69 46 44 4d 62 70 78 76 52 5a 69 61 74 69 71 5a 6e 75 67 5a 62 78 72 51 }
      $op2 = { 23 71 59 72 51 6d 58 48 4a 77 65 55 53 76 68 79 4f 62 51 50 6d 44 44 52 44 6e 72 49 53 57 6c 72 56 4a 56 75 68 52 4e 4a 66 6b 50 6e 6b 72 65 68 73 6e 6b 68 54 4e 70 6a 56 7a 7a 64 61 44 6e 62 44 67 5a 54 62 4b 65 63 54 69 35 4f 71 20 64 24 2d }
   condition:
      uint16(0) == 0x5a4d and filesize > 40KB and 6 of ($s*) and 1 of ($op*)
}
