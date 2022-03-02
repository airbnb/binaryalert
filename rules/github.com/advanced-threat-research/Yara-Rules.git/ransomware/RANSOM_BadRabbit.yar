import "pe"

rule BadBunny {
   
   meta:

      description = "Bad Rabbit Ransomware"
      author = "Christiaan Beek"
      date = "2017-10-24"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/BadRabbit"
      actor_type = "Cybercrime"
      actor_group = "Unknown"    
      hash1 = "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93"
   
   strings:

      $x1 = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" fullword wide
      $x2 = "need to do is submit the payment and get the decryption password." fullword ascii
      $s3 = "If you have already got the password, please enter it below." fullword ascii
      $s4 = "dispci.exe" fullword wide
      $s5 = "\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)" fullword wide
      $s6 = "Run DECRYPT app at your desktop after system boot" fullword ascii
      $s7 = "Enter password#1: " fullword wide
      $s8 = "Enter password#2: " fullword wide
      $s9 = "C:\\Windows\\cscc.dat" fullword wide
      $s10 = "schtasks /Delete /F /TN %ws" fullword wide
      $s11 = "Password#1: " fullword ascii
      $s12 = "\\AppData" fullword wide
      $s13 = "Disk decryption completed" fullword wide
      $s14 = "Files decryption completed" fullword wide
      $s15 = "http://diskcryptor.net/" fullword wide
      $s16 = "Your personal installation key#1:" fullword ascii
      $s17 = ".3ds.7z.accdb.ai.asm.asp.aspx.avhd.back.bak.bmp.brw.c.cab.cc.cer.cfg.conf.cpp.crt.cs.ctl.cxx.dbf.der.dib.disk.djvu.doc.docx.dwg." wide
      $s18 = "Disable your anti-virus and anti-malware programs" fullword wide
      $s19 = "bootable partition not mounted" fullword ascii
   
   condition:
   
      ( uint16(0) == 0x5a4d and
      filesize < 400KB and 
      pe.imphash() == "94f57453c539227031b918edd52fc7f1" and 
      ( 1 of ($x*) or
      4 of them )) or
      ( all of them )
}

rule badrabbit_ransomware {
   
   meta:

      description = "Rule to detect Bad Rabbit Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/BadRabbit"
      actor_type = "Cybercrime"
      actor_group = "Unknown" 
      reference = "https://securelist.com/bad-rabbit-ransomware/82851/"

   strings:
   
      $s1 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR \"%ws /C Start \\\"\\\" \\\"%wsdispci.exe\\\" -id %u && exit\"" fullword wide
      $s2 = "C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\" fullword wide
      $s3 = "process call create \"C:\\Windows\\System32\\rundll32.exe" fullword wide
      $s4 = "need to do is submit the payment and get the decryption password." fullword wide
      $s5 = "schtasks /Create /SC once /TN drogon /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" fullword wide
      $s6 = "rundll32 %s,#2 %s" fullword ascii
      $s7 = " \\\"C:\\Windows\\%s\\\" #1 " fullword wide
      $s8 = "Readme.txt" fullword wide
      $s9 = "wbem\\wmic.exe" fullword wide
      $s10 = "SYSTEM\\CurrentControlSet\\services\\%ws" fullword wide

      $og1 = { 39 74 24 34 74 0a 39 74 24 20 0f 84 9f }
      $og2 = { 74 0c c7 46 18 98 dd 00 10 e9 34 f0 ff ff 8b 43 }
      $og3 = { 8b 3d 34 d0 00 10 8d 44 24 28 50 6a 04 8d 44 24 }

      $oh1 = { 39 5d fc 0f 84 03 01 00 00 89 45 c8 6a 34 8d 45 }
      $oh2 = { e8 14 13 00 00 b8 ff ff ff 7f eb 5b 8b 4d 0c 85 }
      $oh3 = { e8 7b ec ff ff 59 59 8b 75 08 8d 34 f5 48 b9 40 }

      $oj4 = { e8 30 14 00 00 b8 ff ff ff 7f 48 83 c4 28 c3 48 }
      $oj5 = { ff d0 48 89 45 e0 48 85 c0 0f 84 68 ff ff ff 4c }
      $oj6 = { 85 db 75 09 48 8b 0e ff 15 34 8f 00 00 48 8b 6c }

      $ok1 = { 74 0c c7 46 18 c8 4a 40 00 e9 34 f0 ff ff 8b 43 }
      $ok2 = { 68 f8 6c 40 00 8d 95 e4 f9 ff ff 52 ff 15 34 40 }
      $ok3 = { e9 ef 05 00 00 6a 10 58 3b f8 73 30 8b 45 f8 85 }


   condition:

      uint16(0) == 0x5a4d and
      filesize < 1000KB and
      (all of ($s*) and
      all of ($og*)) or
      all of ($oh*) or
      all of ($oj*) or
      all of ($ok*)
}
