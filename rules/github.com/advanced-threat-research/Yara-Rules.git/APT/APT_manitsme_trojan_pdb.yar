rule apt_manitsme_trojan {
  
   meta:
  
      description = "Rule to detect the Manitsme trojan"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2013-03-08"
      rule_version = "v1"
      malware_type = "trojan"
      malware_family = "Trojan:W32/Manitsme"
      actor_type = "Apt"
      actor_group = "Unknown"
      reference = "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
      hash = "c1c0ea096ec4d36c1312171de2a9ebe258c588528a20dbb06a7e3cf97bf1e197"
  
   strings:
  
      $s1 = "SvcMain.dll" fullword ascii
      $s2 = "rj.soft.misecure.com" fullword ascii
      $s3 = "d:\\rouji\\SvcMain.pdb" fullword ascii
      $s4 = "constructor or from DllMain." fullword ascii
      $s5 = "Open File Error" fullword ascii
      $s6 = "nRet == SOCKET_ERROR" fullword ascii
      $s7 = "Oh,shit" fullword ascii
      $s8 = "Paraing" fullword ascii
      $s9 = "Hallelujah" fullword ascii
      $s10 = "ComSpec" fullword ascii /* Goodware String - occured 11 times */
      $s11 = "ServiceMain" fullword ascii /* Goodware String - occured 486 times */
      $s12 = "SendTo(s,(char *)&sztop,sizeof(sztop),FILETYPE) == ERRTYPE" fullword ascii
  
   condition:

      uint16(0) == 0x5a4d and 
      filesize < 200KB and 
      all of them
}