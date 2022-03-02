import "pe"

rule SAmSAmRansom2016 {
   
   meta:

      author = "Christiaan Beek | McAfee ATR Team"
      date = "2018-01-25"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/SamSam"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash1 = "45e00fe90c8aa8578fce2b305840e368d62578c77e352974da6b8f8bc895d75b"
   
   strings:

      $x1 = "Could not list processes locking resource. Failed to get size of result." fullword wide
      $s2 = "Could not list processes locking resource." fullword wide
      $s3 = "samsam.del.exe" fullword ascii
      $s4 = "samsam.exe" fullword wide
      $s5 = "RM_UNIQUE_PROCESS" fullword ascii
      $s6 = "KillProcessWithWait" fullword ascii
      $s7 = "killOpenedProcessTree" fullword ascii
      $s8 = "RM_PROCESS_INFO" fullword ascii
      $s9 = "Exception caught in process: {0}" fullword wide
      $s10 = "Could not begin restart session.  Unable to determine file locker." fullword wide
      $s11 = "samsam.Properties.Resources.resources" fullword ascii
      $s12 = "EncryptStringToBytes" fullword ascii
      $s13 = "recursivegetfiles" fullword ascii
      $s14 = "RSAEncryptBytes" fullword ascii
      $s15 = "encryptFile" fullword ascii
      $s16 = "samsam.Properties.Resources" fullword wide
      $s17 = "TSSessionId" fullword ascii
      $s18 = "Could not register resource." fullword wide
      $s19 = "<recursivegetfiles>b__0" fullword ascii
      $s20 = "create_from_resource" fullword ascii

      $op0 = { 96 00 e0 00 29 00 0b 00 34 23 }
      $op1 = { 96 00 12 04 f9 00 34 00 6c 2c }
      $op2 = { 72 a5 0a 00 70 a2 06 20 94 }
   
   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 700KB and
      pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and
      ( 1 of ($x*) and
      4 of them ) and
      all of ($op*)) or
      ( all of them )
}

rule SamSam_Ransomware_Latest
{

      meta:

            description = "Latest SamSA ransomware samples"
            author = "Christiaan Beek"
            date = "2018-01-23"
            rule_version = "v1"
            malware_type = "ransomware"
            malware_family = "Ransom:W32/SamSam"
            actor_type = "Cybercrime"
            actor_group = "Unknown"
            reference = "http://blog.talosintelligence.com/2018/01/samsam-evolution-continues-netting-over.html"
            hash = "88e344977bf6451e15fe202d65471a5f75d22370050fe6ba4dfa2c2d0fae7828"
         
      strings:

            $s1 = "bedf08175d319a2f879fe720032d11e5" fullword wide
            $s2 = "ksdghksdghkddgdfgdfgfd" fullword ascii
            $s3 = "osieyrgvbsgnhkflkstesadfakdhaksjfgyjqqwgjrwgehjgfdjgdffg" fullword ascii
            $s4 = "5c2d376c976669efaf9cb107f5a83d0c" fullword wide
            $s5 = "B917754BCFE717EB4F7CE04A5B11A6351EEC5015" fullword ascii
            $s6 = "f99e47c1d4ccb2b103f5f730f8eb598a" fullword wide
            $s7 = "d2db284217a6e5596913e2e1a5b2672f" fullword wide
            $s8 = "0bddb8acd38f6da118f47243af48d8af" fullword wide
            $s9 = "f73623dcb4f62b0e5b9b4d83e1ee4323" fullword wide
            $s10 = "916ab48e32e904b8e1b87b7e3ced6d55" fullword wide
            $s11 = "c6e61622dc51e17195e4df6e359218a2" fullword wide
            $s12 = "2a9e8d549af13031f6bf7807242ce27f" fullword wide
            $s13 = "e3208957ad76d2f2e249276410744b29" fullword wide
            $s14 = "b4d28bbd65da97431f494dd7741bee70" fullword wide
            $s15 = "81ee346489c272f456f2b17d96365c34" fullword wide
            $s16 = "94682debc6f156b7e90e0d6dc772734d" fullword wide
            $s17 = "6943e17a989f11af750ea0441a713b89" fullword wide
            $s18 = "b1c7e24b315ff9c73a9a89afac5286be" fullword wide
            $s19 = "90928fd1250435589cc0150849bc0cff" fullword wide
            $s20 = "67da807268764a7badc4904df351932e" fullword wide

            $op0 = { 30 01 00 2b 68 79 33 38 68 34 77 65 36 34 74 72 }
            $op1 = { 01 00 b2 04 00 00 01 00 84 }
            $op2 = { 68 09 00 00 38 66 00 00 23 55 53 00 a0 6f 00 00 }
   
      condition:

            ( uint16(0) == 0x5a4d and
            filesize < 100KB and
            pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and
            ( 8 of them ) and
            all of ($op*)) or
            ( all of them )
}
