rule Mem_Cryptor_Obsidium_Oct_2020_1 {
   meta:
      description = "Detect Obsidium cryptor by memory string"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-10-25"
   strings:
      $s1 = "Obsidium\\" fullword ascii
      $s2 = "obsidium.dll" fullword ascii
      $s3 = "Software\\Obsidium" fullword ascii
      $s4 = "winmm.dll" fullword ascii
      $s5 = "'license.key" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 40KB and 3 of ($s*) 
}
