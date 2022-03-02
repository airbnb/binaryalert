rule Ransom_Maze {
   
   meta:
   
      description = "Detecting MAZE Ransomware"
      author = "McAfee ATR"
      date = "2020-04-19"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Maze"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash = "5badaf28bde6dcf77448b919e2290f95cd8d4e709ef2d699aae21f7bae68a76c"

   strings:

      $x1 = "process call create \"cmd /c start %s\"" fullword wide
      $s1 = "%spagefile.sys" fullword wide
      $s2 = "%sswapfile.sys" fullword wide
      $s3 = "%shiberfil.sys" fullword wide
      $s4 = "\\wbem\\wmic.exe" fullword wide
      $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko" fullword ascii
      $s6 = "NO MUTEX | " fullword wide
      $s7 = "--nomutex" fullword wide
      $s8 = ".Logging enabled | Maze" fullword wide
      $s9 = "DECRYPT-FILES.txt" fullword wide

      $op0 = { 85 db 0f 85 07 ff ff ff 31 c0 44 44 44 44 5e 5f }
      $op1 = { 66 90 89 df 39 ef 89 fb 0f 85 64 ff ff ff eb 5a }
      $op2 = { 56 e8 34 ca ff ff 83 c4 08 55 e8 0b ca ff ff 83 }

   condition:
      ( uint16(0) == 0x5a4d and
      filesize < 500KB and
      ( 1 of ($x*) and
      4 of them ) and
      all of ($op*)) or
      ( all of them )
}

