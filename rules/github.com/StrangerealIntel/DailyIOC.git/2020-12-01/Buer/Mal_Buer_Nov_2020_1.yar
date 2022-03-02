
rule Ins_NSIS_Buer_Nov_2020_1 {
   meta:
      description = "Detect NSIS installer used for Buer loader"
      author = "Arkbird_SOLG"
      reference1 = "https://twitter.com/ffforward/status/1333703755439742977"
      reference2 = "https://twitter.com/VK_Intel/status/1333647007920033793"
      reference3 = "https://twitter.com/James_inthe_box/status/1333551419735953409"
      date = "2020-12-01"
      level = "Experimental"
      hash1 = "b298ead0400aaf886dbe0a0720337e6f2efd5e2a3ac1a7e7da54fc7b6e4f4277"
      hash2 = "66f5a68f6b5067feb07bb88a3bfaa6671a5e8fcf525e9cd2355de631c4ca2088"
      hash3 = "1c8260f2d597cfc1922ca72162e1eb3f8272c2d18fa41d77b145d32256c0063d"
   strings:
      $s1 = "\\Microsoft\\Internet Explorer\\Quick Launch" fullword ascii
      $s2 = "Software\\Microsoft\\Windows\\CurrentVersion" fullword ascii
      $s3 = "Control Panel\\Desktop\\ResourceLocale" fullword ascii
      $s4 = { 25 73 25 73 2e 64 6c 6c }
      $s5 = "CRYPTBASE" fullword ascii
      $s6 = { 25 75 2e 25 75 25 73 25 73 }
      $s7 = "PROPSYS" fullword ascii
      $s8 = { 5b 52 65 6e 61 6d 65 5d 0d 0a 00 00 25 73 3d 25 73 }
      $s9 = "APPHELP" fullword ascii
      $s10 = "NSIS Error" fullword ascii
      $s11 = "K=t%)xMx" fullword ascii
      $s12 = "4/##=?1" fullword ascii
      $dbg1 = "Error launching installer" fullword ascii
      $dbg2 = { 76 65 72 69 66 79 69 6e 67 20 69 6e 73 74 61 6c 6c 65 72 3a 20 25 64 25 25 }
      $dbg3 = { 54 4d 50 00 54 45 4d 50 00 00 00 00 4c 6f 77 00 5c 54 65 6d 70 00 00 00 20 2f 44 3d 00 00 00 00 4e 43 52 43 }
      $dbg4 = { e8 73 2a 00 00 3b fb 74 0b 68 4c a1 40 00 56 e8 64 2a 00 00 68 44 a1 40 00 56 e8 59 2a 00 00 bd 00 5c 43 00 55 56 ff 15 18 81 40 00 85 c0 74 97 3b fb 56 74 07 e8 0f 20 00 00 eb 05 e8 85 20 00 00 56 ff 15 f8 80 40 00 38 1d 00 54 43 00 75 0b 55 68 00 54 43 00 e8 01 2a 00 00 ff 74 24 1c 68 00 00 43 00 e8 f3 29 00 00 66 0f be 0d 40 a1 40 00 33 c0 6a 1a 8a 25 41 }
   condition:
      uint16(0) == 0x5a4d and filesize > 40KB and ( 10 of ($s*) and 3 of ($dbg*) )
}

rule Loader_Buer_Nov_2020_1 {
   meta:
      description = "Detect Buer loader"
      author = "Arkbird_SOLG"
      reference1 = "https://twitter.com/ffforward/status/1333703755439742977"
      reference2 = "https://twitter.com/VK_Intel/status/1333647007920033793"
      reference3 = "https://twitter.com/James_inthe_box/status/1333551419735953409"
      date = "2020-12-01"
      hash1 = "2824d4b0e5a502416696b189bd840870a19dfd555b53535f20b0c87c95f4c232"
      hash2 = "a98abbce5e84c4c3b67b7af3f9b4dc9704b5af33b6183fb3c192e26b1e0ca005"
      hash3 = "ae3ac27e8303519cf04a053a424a0939ecc3905a9a62f33bae3a29f069251b1f"
   strings:
      $s1 = "bcdfghklmnpqrstvwxz" fullword ascii
      $s2 = "%02x" fullword wide
      $s3 = "{%s-%d-%d}" fullword wide
      $s4 = "update" fullword wide 
      //opcode loader
      $s5 = "]otju}y&Ykx|kx&867?5Ykx|kx&867<" fullword ascii
      $s6 = "]otju}y&Ykx|kx&8678&X8" fullword ascii
      $s7 = "]otju}y&\\oyzg5Ykx|kx&857>" fullword ascii
      $s8 = "]otju}y&>47" fullword ascii
      $s9 = "]otju}y&Ykx|kx&8678" fullword ascii
      $s10 = "]otju}y&=" fullword ascii
      $s11 = "Iutzktz3Z" fullword ascii
      $s12 = "g|mnuuq~4jrr" fullword ascii
      $s13 = "RegularModules" fullword ascii
      $s14 = "]otju}y&>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 10KB and 8 of them
}
