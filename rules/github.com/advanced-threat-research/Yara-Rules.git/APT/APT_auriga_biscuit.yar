rule apt_auriga_driver {
   
   meta:
   
      description = "Rule to detect the Auriga driver"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2013-03-13"
      reference = "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
      rule_version = "v1"
      malware_type = "kerneldriver"
      malware_family = "Driver:W32/Auriga"
      actor_type = "APT"
      actor_group = "APT1"
      hash = "207eee627a76449ac6d2ca43338d28087c8b184e7b7b50fdc60a11950c8283ec"
   
   strings:
   
      $s1 = "\\SystemRoot\\System32\\netui.dll" fullword wide
      $s2 = "\\SystemRoot\\System32\\drivers\\riodrv32.sys" fullword wide
      $s3 = "\\SystemRoot\\System32\\arp.exe" fullword wide
      $s4 = "netui.dll" fullword ascii
      $s5 = "riodrv32.sys" fullword wide
      $s6 = "\\netui.dll" fullword wide
      $s7 = "d:\\drizt\\projects\\auriga\\branches\\stone_~1\\server\\exe\\i386\\riodrv32.pdb" fullword ascii
      $s8 = "\\riodrv32.sys" fullword wide
      $s9 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\riodrv32" fullword wide
      $s10 = "\\DosDevices\\rio32drv" fullword wide
      $s11 = "e\\Driver\\nsiproxy" fullword wide
      $s12 = "(C) S3/Diamond Multimedia Systems. All rights reserved." fullword wide
      $s13 = "\\Device\\rio32drv" fullword wide
      $s14 = "\\Registry\\Machine\\SOFTWARE\\riodrv" fullword wide
      $s15 = "\\Registry\\Machine\\SOFTWARE\\riodrv32" fullword wide
   
   condition:
   
      uint16(0) == 0x5a4d and 
      filesize < 50KB and 
      all of them
}