rule pico_ransomware {
   
   meta:
   
      description = "Rule to detect Pico Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-08-30"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Pico"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://twitter.com/siri_urz/status/1035138577934557184"
      hash = "cc4a9e410d38a29d0b6c19e79223b270e3a1c326b79c03bec73840b37778bc06"
      
   strings:

      $s1 = "C:\\Users\\rikfe\\Desktop\\Ransomware\\ThanatosSource\\Release\\Ransomware.pdb" fullword ascii
      $s2 = "\\Downloads\\README.txt" fullword ascii
      $s3 = "\\Music\\README.txt" fullword ascii
      $s4 = "\\Videos\\README.txt" fullword ascii
      $s5 = "\\Pictures\\README.txt" fullword ascii
      $s6 = "\\Desktop\\README.txt" fullword ascii
      $s7 = "\\Documents\\README.txt" fullword ascii
      $s8 = "/c taskkill /im " fullword ascii
      $s9 = "\\AppData\\Roaming\\" fullword ascii
      $s10 = "gMozilla/5.0 (Windows NT 6.1) Thanatos/1.1" fullword wide
      $s11 = "AppData\\Roaming" fullword ascii
      $s12 = "\\Downloads" fullword ascii
      $s13 = "operator co_await" fullword ascii
   
   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 700KB ) and
      all of them
}
