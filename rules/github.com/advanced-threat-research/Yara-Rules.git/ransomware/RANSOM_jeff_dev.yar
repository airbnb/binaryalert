rule jeff_dev_ransomware {

   meta:
   
      description = "Rule to detect Jeff Dev Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-08-26"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Jeff"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
      hash = "386d4617046790f7f1fcf37505be4ffe51d165ba7cbd42324aed723288ca7e0a"
      
   strings:

      $s1 = "C:\\Users\\Umut\\Desktop\\takemeon" fullword wide
      $s2 = "C:\\Users\\Umut\\Desktop\\" fullword ascii
      $s3 = "PRESS HERE TO STOP THIS CREEPY SOUND AND VIEW WHAT HAPPENED TO YOUR COMPUTER" fullword wide
      $s4 = "WHAT YOU DO TO MY COMPUTER??!??!!!" fullword wide

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 5000KB ) and
      all of them
}
