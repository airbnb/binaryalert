rule APT_Turla_ComRAT_Chinch_V4_Jan_2021_1 {
   meta:
      description = "Detect ComRAT V4 (Chinch) used by APT Turla group"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2021-01-23"
      hash1 = "a62e1a866bc248398b6abe48fdb44f482f91d19ccd52d9447cda9bc074617d56"
   strings:
      $com1 = "state->_reprocess_current_token || token.type != GUMBO_TOKEN_START_TAG || token.v.start_tag.attributes.data == NULL" fullword wide
      $com2 = "fragment_ctx != GUMBO_TAG_LAST" fullword wide
      $com3 = "has_matching_a == 1" fullword wide
      $com4 = "ODFA: %u %d %u" fullword ascii
      $com5 = "Custom browser path is empty." fullword ascii
      $com6 = "Default browser path is:" fullword ascii
      $com7 = "Search for browser path." fullword ascii
      $com8 = "Cant retrieve any path." fullword ascii
      $com9 = "Custom browser path is:" fullword ascii
      // ref to export jump
      $jmp1  = { 2e 64 6c 6c 00 55 4d 45 50 00 56 46 45 50 }
      $jmp2 = { 33 c9 e9 ?? ?? ff ff cc cc cc cc cc cc cc cc cc }
      $seq1 = { 40 55 48 8d ac 24 00 fd ff ff 48 81 ec 00 04 00 00 48 8b 05 80 46 1b 00 48 33 c4 48 89 85 d0 02 00 00 b9 d8 02 00 00 e8 f4 8b 07 00 4c 8b 0d c5 a5 1c 00 48 8d 95 00 01 00 00 4c 8b 05 af a5 1c 00 48 8d 0d c8 9d 1c 00 4d 2b c8 48 89 05 ae 8a 1d 00 e8 a9 7e fc ff 48 83 bd 18 01 00 00 10 48 8d 8d 00 01 00 00 48 0f 43 8d 00 01 00 00 ff 15 24 f3 0c 00 48 8b 15 25 f3 0c 00 48 8b c8 e8 6d 59 fb ff 48 8b 95 18 01 00 00 48 83 fa 10 }
      // flush variant 
      $seq2 = { 41 8b 41 08 83 e8 09 83 f8 08 }
      $seq3 = { 48 8b 03 48 8b cb ff 50 08 48 8b 95 f8 01 00 00 48 83 fa 08 72 39 48 8b 8d e0 }
      $seq4 = { b8 09 00 00 00 44 88 a5 60 01 00 00 48 8d 8d 60 01 00 00 f3 0f 7f 85 70 01 00 00 e8 c1 19 fc ff ba df 5e ca 76 48 8d 4d 50 e8 63 ea fc ff 48 8b c8 48 8d 95 60 01 00 00 e8 c4 cb ff ff 0f b6 15 dd 8b 1c 00 48 8b c8 e8 35 cd ff ff 48 8b 95 78 01 00 00 48 83 fa 10 72 34 }
   condition:
      uint16(0) == 0x5a4d and filesize > 1000KB and 6 of ($com*) and all of ($jmp*) and 3 of ($seq*)
}
