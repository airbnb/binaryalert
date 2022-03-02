rule bitpaymer_ransomware {
   
   meta:
   
      description = "Rule to detect BitPaymer Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-11-08"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/BitPaymer"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/spanish-mssp-targeted-by-bitpaymer-ransomware/"
        
   strings:

      $s1 = "IEncrypt.dll" fullword wide
      $op0 = { e8 5f f3 ff ff ff b6 e0 }
      $op1 = { e8 ad e3 ff ff 59 59 8b 75 08 8d 34 f5 38 eb 42 }
      $op2 = { e9 45 ff ff ff 33 ff 8b 75 0c 6a 04 e8 c1 d1 ff }

      $pdb = "S:\\Work\\_bin\\Release-Win32\\wp_encrypt.pdb" fullword ascii
      $oj0 = { 39 74 24 34 75 53 8d 4c 24 18 e8 b8 d1 ff ff ba }
      $oj1 = { 5f 8b c6 5e c2 08 00 56 8b f1 8d 4e 34 e8 91 af }
      $oj2 = { 8b cb 8d bd 50 ff ff ff 8b c1 89 5f 04 99 83 c1 }

      $t1 = ".C:\\aaa_TouchMeNot_.txt" fullword wide
      $ok0 = { e8 b5 34 00 00 ff 74 24 18 8d 4c 24 54 e8 80 39 }
      $ok1 = { 8b 5d 04 33 ff 8b 44 24 34 89 44 24 5c 85 db 7e }
      $ok2 = { 55 55 ff 74 24 20 8d 4c 24 34 e8 31 bf 00 00 55 }

      $random = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+" fullword ascii
      $oi0 = { a1 04 30 ac 00 8b ce 0f af c2 03 c0 99 8b e8 89 }
      $oi1 = { e8 64 a2 ff ff 85 c0 74 0c 8d 4d d8 51 ff 35 64 }
      $oi2 = { c7 03 d4 21 ac 00 e8 86 53 00 00 89 73 10 89 7b }
      $ou0 = { e8 64 a2 ff ff 85 c0 74 0c 8d 4d d8 51 ff 35 60 }
      $ou1 = { a1 04 30 04 00 8b ce 0f af c2 03 c0 99 8b e8 89 }
      $ou2 = { 8d 4c 24 10 e8 a0 da ff ff 68 d0 21 04 00 8d 4c }
      $oa1 = { 56 52 ba 00 10 0c 00 8b f1 e8 28 63 00 00 8b c6 }
      $oa2 = { 81 3d 50 30 0c 00 53 c6 d2 43 56 8b f1 75 23 ba }
      $oy0 = { c7 06 cc 21 a6 00 c7 46 08 }
      $oy1 = { c7 06 cc 21 a6 00 c7 46 08 }
      $oy2 = { c7 06 cc 21 a6 00 c7 46 08 }
      $oh1 = { e8 74 37 00 00 a3 00 30 fe 00 8d 4c 24 1c 8d 84 }
      $oh2 = { 56 52 ba 00 10 fe 00 8b f1 e8 28 63 00 00 8b c6 }

   condition:

      (uint16(0) == 0x5a4d and
      filesize < 1000KB) and
      ($s1 and
      all of ($op*)) or
      ($pdb and
      all of ($oj*)) or
      ($t1 and
      all of ($ok*)) or
      ($random and
      all of ($oi*)) or
      ($random and
      all of ($ou*)) or
      ($random and
      all of ($oa*) and
      $ou0) or
      ($random and
      all of ($oy*)) or
      ($random and
      all of ($oh*)) or
      ($random and
      $ou0) or
      ($random and
      $oi1)
}
