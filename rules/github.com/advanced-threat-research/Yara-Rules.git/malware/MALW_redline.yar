rule redline_payload {
   
   meta:
     
      description = "Rule to detect the RedLine payload"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-04-16"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:W32/RedLine"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.proofpoint.com/us/threat-insight/post/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"
      hash = "5df956f08d6ad0559efcdb7b7a59b2f3b95dee9e2aa6b76602c46e2aba855eff"
      
   strings:

      $s1 = "Cambrel.exe" fullword ascii

      //TextInputFramework.DYNLINK
      $s2 = { 22 00 54 00 65 00 78 00 74 00 49 00 6e 00 70 00 75 00 74 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 2e 00 44 00 59 00 4e 00 4c 00 49 00 4e 00 4b 00 22 00 }

      $op0 = { 06 7c 34 00 00 04 7b 17 00 00 04 7e 21 00 00 0a }
      $op1 = { 96 00 92 0e 83 02 02 00 f4 20 }
      $op2 = { 03 00 c6 01 d9 08 1b 03 44 }

      $p0 = { 80 00 96 20 83 11 b7 02 10 }
      $p1 = { 20 01 00 72 0f 00 20 02 00 8a 0f 00 20 03 00 61 }
      $p2 = { 03 00 c6 01 cd 06 13 03 79 }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 60KB and
      all of ($s*) and
      all of ($op*) or
      all of ($p*) 
}
