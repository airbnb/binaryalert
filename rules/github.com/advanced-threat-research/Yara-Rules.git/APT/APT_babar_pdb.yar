rule apt_babar_malware {

   meta:

      description = "Rule to detect Babar malware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2015-02-18"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:W32/Babar"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france"
      hash = "c72a055b677cd9e5e2b2dcbba520425d023d906e6ee609b79c643d9034938ebf"

   strings:

      $s1 = "c:\\Documents and Settings\\admin\\Desktop\\Babar64\\Babar64\\obj\\DllWrapper Release\\Release.pdb" fullword ascii
      $s2 = "%COMMON_APPDATA%" fullword ascii
      $s3 = "%%WINDIR%%\\%s\\%s" fullword ascii
      $s4 = "/s /n %s \"%s\"" fullword ascii
      $s5 = "/c start /wait " fullword ascii
      $s6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" fullword ascii
      $s7 = "constructor or from DllMain." fullword ascii
      $s8 = "ComSpec" fullword ascii 
      $s9 = "APPDATA" fullword ascii 
      $s10 = "WINDIR" fullword ascii 
      $s11 = "USERPROFILE" fullword ascii 
   
   condition:

      uint16(0) == 0x5a4d and 
      filesize < 2000KB and 
      all of them
}