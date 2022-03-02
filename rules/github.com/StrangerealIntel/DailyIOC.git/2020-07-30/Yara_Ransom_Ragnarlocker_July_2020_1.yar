import "pe"

rule Ransom_Ragnarlocker_July_2020_1 {
   meta:
      description = "Detect Ragnarlocker by strings (July 2020)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/JAMESWT_MHT/status/1288797666688851969"
      date = "2020-07-30"
      hash1 = "04c9cc0d1577d5ee54a4e2d4dd12f17011d13703cdd0e6efd46718d14fd9aa87"
   strings:
      $f1 = "bootfont.bin" fullword wide
      $f2 = "bootmgr.efi" fullword wide
      $f3 = "bootsect.bak" fullword wide
      $r1 = "$!.txt" fullword wide
      $r2 = "---BEGIN KEY R_R---" fullword ascii
      $r3 = "!$R4GN4R_" fullword wide
      $r4 = "RAGNRPW" fullword ascii /* parser */
      $r5 = "---END KEY R_R---" fullword ascii
      $a1 = "+RhRR!-uD8'O&Wjq1_P#Rw<9Oy?n^qSP6N{BngxNK!:TG*}\\|W]o?/]H*8z;26X0" fullword ascii    
      $a2 = "\\\\.\\PHYSICALDRIVE%d" fullword wide /* parse disks */
      $a3 = "WinSta0\\Default" fullword wide /* Token ref */
      $a4 = "%s-%s-%s-%s-%s" fullword wide /* GUID parser*/
      $a5 = "SOFTWARE\\Microsoft\\Cryptography" fullword wide /* Ref crypto used */
      $c1 = "-backup" fullword wide
      $c2 = "-force" fullword wide
      $c3 = "-vmback" fullword wide
      $c4 = "-list" fullword wide
      $s1 = ".ragn@r_" fullword wide /* ref */
      $s2 = "\\notepad.exe" fullword wide /* Show ransom note to the victim*/
      $s3 = "Opera Software" fullword wide  /* Don't touch browsers for contact him*/
      $s4 = "Tor browser" fullword wide /*Ref ransom note*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and ( pe.imphash() == "2c2aab89a4cba444cf2729e2ed61ed4f" and ( (2 of ($f*)) and (3 of ($r*)) and (4 of ($a*)) and (2 of ($c*)) and (2 of ($s*)) ) )
}
