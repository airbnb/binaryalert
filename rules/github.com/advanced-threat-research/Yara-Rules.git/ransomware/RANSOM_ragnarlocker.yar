import "pe"

rule ragnarlocker_ransomware {

   meta:
   
      description = "Rule to detect RagnarLocker samples"
      author = "McAfee ATR Team"
      date = "2020-04-15"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/RagnarLocker"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.bleepingcomputer.com/news/security/ragnar-locker-ransomware-targets-msp-enterprise-support-tools/"
      hash = "9706a97ffa43a0258571def8912dc2b8bf1ee207676052ad1b9c16ca9953fc2c"
      
   strings:
   
      //---RAGNAR SECRET---
      $s1 = {2D 2D 2D 52 41 47 4E 41 52 20 53 45 43 52 45 54 2D 2D 2D}
      $s2 = { 66 ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? B8 ?? ?? ?? ?? 0F 44 }
      $s3 = { 5? 8B ?? 5? 5? 8B ?? ?? 8B ?? 85 ?? 0F 84 }
      $s4 = { FF 1? ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 85 }
      $s5 = { 8D ?? ?? ?? ?? ?? 5? FF 7? ?? E8 ?? ?? ?? ?? 85 ?? 0F 85 }
      
      $op1 = { 0f 11 85 70 ff ff ff 8b b5 74 ff ff ff 0f 10 41 }
      
      $p0 = { 72 eb fe ff 55 8b ec 81 ec 00 01 00 00 53 56 57 }
      $p1 = { 60 be 00 00 41 00 8d be 00 10 ff ff 57 eb 0b 90 }
      
      $bp0 = { e8 b7 d2 ff ff ff b6 84 }
      $bp1 = { c7 85 7c ff ff ff 24 d2 00 00 8b 8d 7c ff ff ff }
      $bp2 = { 8d 85 7c ff ff ff 89 85 64 ff ff ff 8d 4d 84 89 }
      
   condition:
   
     uint16(0) == 0x5a4d and 
     filesize < 100KB and 
     (4 of ($s*) and $op1) or
     all of ($p*) and
     pe.imphash() == "9f611945f0fe0109fe728f39aad47024" or
     all of ($bp*) and
     pe.imphash() == "489a2424d7a14a26bfcfb006de3cd226" 
}
