rule amba_ransomware {
   
   meta:

      description = "Rule to detect Amba Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2017-07-03"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Amba"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.enigmasoftware.com/ambaransomware-removal/"
      hash = "b9b6045a45dd22fcaf2fc13d39eba46180d489cb4eb152c87568c2404aecac2f"

   strings:

      $s1 = "64DCRYPT.SYS" fullword wide
      $s2 = "32DCRYPT.SYS" fullword wide
      $s3 = "64DCINST.EXE" fullword wide
      $s4 = "32DCINST.EXE" fullword wide
      $s5 = "32DCCON.EXE" fullword wide
      $s6 = "64DCCON.EXE" fullword wide
      $s8 = "32DCAPI.DLL" fullword wide
      $s9 = "64DCAPI.DLL" fullword wide
      $s10 = "ICYgc2h1dGRvd24gL2YgL3IgL3QgMA==" fullword ascii 
      $s11 = "QzpcVXNlcnNcQUJDRFxuZXRwYXNzLnR4dA==" fullword ascii 
      $s12 = ")!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v)" fullword ascii
      $s13 = "RGVmcmFnbWVudFNlcnZpY2U=" 
      $s14 = "LWVuY3J5cHQgcHQ5IC1wIA==" 
      $s15 = "LWVuY3J5cHQgcHQ3IC1wIA==" 
      $s16 = "LWVuY3J5cHQgcHQ2IC1wIA==" 
      $s17 = "LWVuY3J5cHQgcHQzIC1wIA==" 

   condition:
   
      ( uint16(0) == 0x5a4d and
      filesize < 3000KB and
      ( 8 of them )) or
      ( all of them )
}
