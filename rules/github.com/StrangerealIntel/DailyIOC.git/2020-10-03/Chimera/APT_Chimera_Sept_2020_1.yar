rule APT_Chimera_Sept_2020_1 {
   meta:
      description = "Detect Cobalt Strike agent used by Chimera"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      // ref article : https://cycraft.com/download/%5BTLP-White%5D20200415%20Chimera_V4.1.pdf
      date = "2020-10-03"
      hash1 = "f6d89ff139f4169e8a67332a0fd55b6c9beda0b619b1332ddc07d9a860558bab"
   strings:
      $header = { 4D 5A 41 52 55 48 89 E5 48 83 EC 20 48 83 E4 F0 E8 00 00 00 00 5B 48 81 C3 EB 18 00 00 FF D3 48 81 C3 00 09 03 00 49 89 D8 6A 04 5A FF D0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E8 } // MZ header
      $s1 = "\\\\%s\\pipe\\%s" fullword ascii
      $s2 = "%04x-%04x:%s" fullword wide
      $core1 = "core_pivot_session_new" fullword ascii
      $core2 = "core_pivot_session_died" fullword ascii
      $core3 = "core_pivot_remove" fullword ascii
      $core4 = "core_pivot_add" fullword ascii
      $lib1 = "CreateNamedPipeA" fullword ascii
      $lib2 = "ConnectNamedPipe" fullword ascii
      $lib3 = "WinHttpGetIEProxyConfigForCurrentUser" fullword ascii
      $export = "ReflectiveLoader" fullword ascii
   condition:
       uint16(0) == 0x4a5d and filesize > 30KB and $header and 1 of ($s*) and 2 of ($core*) and 2 of ($lib*) and $export
}
