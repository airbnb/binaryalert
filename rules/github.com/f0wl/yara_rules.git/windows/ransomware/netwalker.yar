rule Netwalker : ransomware { 
  meta: 
    description = "Detects Netwalker Ransomware" 
    author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>" 
    reference = "https://github.com/f0wl/configwalker" 
    date = "2020-10-26" // updated 2021-11-29
    hash1 = "4f7bdda79e389d6660fca8e2a90a175307a7f615fa7673b10ee820d9300b5c60"
    hash2 = "46dbb7709411b1429233e0d8d33a02cccd54005a2b4015dcfa8a890252177df9"
    hash3 = "5d869c0e077596bf0834f08dce062af1477bf09c8f6aa0a45d6a080478e45512"
    hash4 = "ce399a2d07c0851164bd8cc9e940b84b88c43ef564846ca654df4abf36c278e6"

  strings: 
    $conf1 = "svcwait" fullword ascii
    $conf2 = "extfree" fullword ascii
    $conf3 = "encname" fullword ascii
    $conf4 = "spsz" fullword ascii
    $conf5 = "idsz" fullword ascii
    $conf6 = "onion1" fullword ascii
    $conf7 = "onion2" fullword ascii
    $conf8 = "lfile" fullword ascii
    $conf9 = "lend" fullword ascii
    $conf10 = "white" fullword ascii
    $conf11 = "extfree" fullword ascii
    $conf12 = "encname" fullword ascii
    
    $s1 = "taskkill /F /PID" fullword ascii
    $s2 = "{code_id:" fullword ascii
    $s3 = "{id}-Readme.txt" fullword wide
    $s4 = "netwalker" wide ascii
    $s5 = "expand 32-byte kexpand 16-byte k" fullword ascii
    $s6 = "InterfacE\\{b196b287-bab4-101a-b69c-00aa00341d07}" fullword ascii
      
  condition: 
    uint16(0) == 0x5a4d 
    and filesize > 45KB // Size on Disk/1.5
    and filesize < 130KB // Size of Image*1.5
    and 6 of ($conf*) 
    and 3 of ($s*)
}