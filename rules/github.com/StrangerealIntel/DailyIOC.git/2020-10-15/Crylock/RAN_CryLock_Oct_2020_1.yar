rule RAN_CryLock_Oct_2020_1 {
   meta:
      description = "Detect CryLock ransomware V2.0.0"
      author = "Arkbird_SOLG"
      reference1 = "https://twitter.com/Kangxiaopao/status/1316334926728318977"
      reference2 = "https://twitter.com/JAMESWT_MHT/status/1316426560803680257"
      date = "2020-10-14"
      hash1 = "04d8109c6c78055d772c01fefe1e5f48a70f2a65535cff17227b5a2c8506b831"
   strings:
      // globals strings 
      $s1 = "All commands sended to execution" fullword ascii
      $s2 = "Processesblacklist1" fullword ascii
      $s3 = "Execute all" fullword ascii
      $s4 = "config.txt" fullword ascii
      // debug output
      $debug1 = "Processed files: " fullword ascii
      $debug2 = "Next -->" fullword ascii
      $debug3 = "Status: scan network" fullword ascii
      $debug4 = { 49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } // IE(AL("%s",4),"AL(\\"%0:s\\",3)","JK(\\"%1:s\\",\\"%0:s\\")")
      $debug5 = { 4a 75 6d 70 49 44 28 22 22 2c 22 25 73 22 29 } // JumpID("","%s")
      $debug6 = { 45 6e 63 72 79 70 74 65 64 20 62 79 20 42 6c 61 63 6b 52 61 62 62 69 74 2e 20 28 [3-10] 29 }  // Encrypted by BlackRabbit. ([3-10]) -> Version ref
      //strings linked to ransom note
      $ran1 = "w_to_decrypt.hta" wide
      $ran2 = "<%UNDECRYPT_DATETIME%>" fullword ascii 
      $ran3 = "<%START_DATETIME%>" fullword ascii 
      $ran4 = "<%MAIN_CONTACT%>" fullword ascii 
      $ran5 = "<%RESERVE_CONTACT%>" fullword ascii
      $ran6 = "<%HID%>" fullword ascii 
   condition:
      uint16(0) == 0x5a4d and filesize > 300KB and 3 of ($s*) and 4 of ($debug*) and 4 of ($ran*)
}
