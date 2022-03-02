rule Ran_Ruyk_Oct_2020_1 {
   meta:
      description = "Detect RYUK ransomware (Sept_2020_V1)"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-10-25"
      hash1 = "bbbf38de4f40754f235441a8e6a4c8bdb9365dab7f5cfcdac77dbb4d6236360b"
      hash2 = "cfe1678a7f2b949966d9a020faafb46662584f8a6ac4b72583a21fa858f2a2e8"
      hash3 = "e8a0e80dfc520bf7e76c33a90ed6d286e8729e9defe6bb7da2f38bc2db33f399"
   strings:
      $c1 = "\" /TR \"C:\\Windows\\System32\\cmd.exe /c for /l %x in (1,1,50) do start wordpad.exe /p " fullword ascii
      $c2 = "cmd.exe /c \"bootstatuspolicy ignoreallfailures\"" fullword ascii
      $c3 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $c4 = "cmd.exe /c \"WMIC.exe shadowcopy delete\"" fullword ascii
      $c5 = "cmd.exe /c \"vssadmin.exe Delete Shadows /all /quiet\"" fullword ascii
      $c6 = "cmd.exe /c \"bcdedit /set {default} recoveryenabled No & bcdedit /set {default}\"" fullword ascii  
      $r1 = "/C REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"EV\" /t REG_SZ /d \"" fullword wide
      $r2 = "/C REG DELETE \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"EV\" /f" fullword wide
      $ref1 = "lsaas.exe" fullword wide
      $ref2 = "Ncsrss.exe" fullword wide
      $ref3 = "$WGetCurrentProcess" fullword ascii
      $ref4 = "lan.exe" fullword wide
      $ref5 = "explorer.exe" fullword wide
      $ref6 = "Ws2_32.dll" fullword ascii
      $p1 = "\\users\\Public\\sys" fullword wide
      $p2 = "\\Documents and Settings\\Default User\\sys" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize > 40KB and 4 of ($c*) and 1 of ($r*) and 4 of ($ref*) and 1 of ($p*)
}
