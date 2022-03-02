rule RAN_Matrix_Sep_2020_1  {
   meta:
      description = "Detect MATRIX ransomware"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-10-15"
      hash1 = "7b5e536827c3bb9f8077aed78726585739bcde796904edd6c4faadc9a8d22eaf"
      hash2 = "afca3b84177133ff859d9b9d620b582d913218723bfcf83d119ec125b88a8c40"
      hash3 = "d87d1fbeffe5b18e22f288780bf50b1e7d5af9bbe2480c80ea2a7497a3d52829"
      hash4 = "5474b58de90ad79d6df4c633fb773053fecc16ad69fb5b86e7a2b640a2a056d6"
   strings:
      $debug1 = "[LDRIVES]: not found!" fullword wide
      $debug2 = "[DONE]: NO_SHARES!" fullword wide
      $debug3 = "[ALL_LOCAL_KID]: " fullword wide
      $debug4 = "[FINISHED]: G=" fullword wide
      $debug5 = "[FEX_START]" fullword wide
      $debug6 = "[LOGSAVED]" fullword wide
      $debug7 = "[GENKEY]" fullword wide
      $debug8 = "[SHARES]" fullword wide
      $debug9 = "[SHARESSCAN]: " fullword wide
      $reg1 = { 2e 00 70 00 68 00 70 00 3f 00 61 00 70 00 69 00 6b 00 65 00 79 00 3d } // .php?apikey= -> add victim to the register
      $reg2 = { 26 00 63 00 6f 00 6d 00 70 00 75 00 73 00 65 00 72 00 3d } // &compuser=
      $reg3 = { 26 00 73 00 69 00 64 00 3d 00 } // &sid=
      $reg4 = { 26 00 70 00 68 00 61 00 73 00 65 00 3d } // &phase=
      $reg5 = { 47 00 45 00 54 } // GET
   condition:
      uint16(0) == 0x5a4d and filesize > 500KB and 4 of ($debug*) and 3 of ($reg*)
}
