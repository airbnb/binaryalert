import "pe" 

rule Ran_Mem_RagnarLocker_Nov_2020_1 {
   meta:
      description = "Detect memory artefacts of the Ragnarlocker ransomware (Nov 2020)"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-11-26"
      hash1 = "041fd213326dd5c10a16caf88ff076bb98c68c052284430fba5f601023d39a14"
      hash2 = "dd79b2abc21e766fe3076038482ded43e5069a1af9e0ad29e06dce387bfae900"
   strings:
      $s1 = "\\\\.\\PHYSICALDRIVE%d" fullword wide
      $s2 = "bootfont.bin" fullword wide
      $s3 = "bootsect.bak" fullword wide
      $s4 = "bootmgr.efi" fullword wide
      $s5 = "---RAGNAR SECRET---" fullword ascii
      $s6 = "Mozilla" 
      $s7 = "Internet Explorer" fullword wide 
      $s8 = "  </trustInfo>" fullword ascii
      $s9 = "Tor browser" fullword wide
      $s10 = "Opera Software" fullword wide 
      $s11 = "---END RAGN KEY---" fullword ascii
      $s12 = "---BEGIN RAGN KEY---" fullword ascii
      $s13 = "%s-%s-%s-%s-%s" fullword wide
      $s14 = "$Recycle.Bin" fullword wide 
      $s15 = "***********************************************************************************" fullword ascii
      $s16 = "K<^_[]" fullword ascii
      $s17 = "SD;SDw" fullword ascii
      $s18 = "Windows.old" fullword wide 
      $s19 = "iconcache.db" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize > 30KB and 12 of them 
}

rule Ran_Cert_RagnarLocker_Nov_2020_1 {
   meta:
      description = "Detect certificates and VMProtect used for the Ragnarlocker ransomware (Nov 2020)"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-11-26"
      level = "Experimental"
      hash1 = "afab912c41c920c867f1b2ada34114b22dcc9c5f3666edbfc4e9936c29a17a68"
      hash2 = "9416e5a57e6de00c685560fa9fee761126569d123f62060792bf2049ebba4151"
   strings:
     $vmp0 = { 2E 76 6D 70 30 00 00 00 }
     $vmp1 = { 2E 76 6D 70 31 00 00 00 }
   condition:
      uint16(0) == 0x5a4d and filesize > 5000KB and 
      for any i in (0 .. pe.number_of_signatures) : (
               pe.signatures[i].issuer contains "GlobalSign" and
               pe.signatures[i].serial == "68:65:29:4f:67:f0:c3:bb:2e:19:1f:75"
            )
      // check vmp sections on the header declaration
      and $vmp0 in (0x100..0x300) and $vmp1 in (0x100..0x300)
}
