import "pe"

rule RANSOM_MountLocker_V2 { 

 meta: 
  description = "Detects Mount Locker Ransomware, Version 2 x86 unpacked" 
  author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>" 
  reference = "https://dissectingmalwa.re/between-a-rock-and-a-hard-place-exploring-mount-locker-ransomware.html" 
  date = "2020-12-20"
  tlp = "WHITE"
  hash1 = "226a723ffb4a91d9950a8b266167c5b354ab0db1dc225578494917fe53867ef2"
  hash2 = "e7c277aae66085f1e0c4789fe51cac50e3ea86d79c8a242ffc066ed0b0548037"

strings: 
  //picks up on the Volume Serial Number Permutation in function mw_mutex
  $mutex_shift = { 8b c1 c1 c8 ?? 50 8b c1 c1 c8 ?? 50 8b c1 c1 c8 ?? 50 51}

  $x1 = "powershell.exe -windowstyle hidden -c $mypid='%u';[System.IO.File]::ReadAllText('%s')|iex" fullword wide
  //$x2 = "explorer.exe RecoveryManual.html" fullword wide
  $x2 = "RecoveryManual.html" wide

  $x3 = "expand 32-byte k" fullword ascii
  $x4 = "<b>/!\\ YOUR NETWORK HAS BEEN HACKED /!\\<br>" fullword ascii

  $s1 = "[SKIP] locker.volume.enum > readonly name=%s" fullword wide
  $s2 = "[WARN] locker.dir.check > get_reparse_point gle=%u name=%s" fullword wide
  $s3 = "[ERROR] locker.file > get_size gle=%u name=%s" fullword wide
  $s4 = "[OK] locker > finished" fullword wide

condition: 
  uint16(0) == 0x5a4d and filesize < 600KB
  and pe.imphash() == "1ea39e61089a4ea253fb896bbcf01be5"
  and $mutex_shift 
  and 2 of ($x*) 
  and 2 of ($s*)
} 
