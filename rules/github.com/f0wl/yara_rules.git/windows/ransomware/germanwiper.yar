rule GermanWiper : ransomware { 
  meta: 
    description = "Detects GermanWiper 'Ransomware'" 
    author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>" 
    reference = "https://dissectingmalwa.re/tfw-ransomware-is-only-your-side-hustle.html" 
    date = "2019-07-31" 
    hash1 = "41364427dee49bf544dcff61a6899b3b7e59852435e4107931e294079a42de7c" 

  strings: 
    $a1 = "C:\\Bewerbung-Lena-Kretschmer.exe" fullword ascii 
    $a2 = "Copyright VMware." fullword ascii
    $a3 = "Friction Tweeter Casting Transferability" fullword ascii
    $a4 = "expandingdelegation.top" fullword ascii
    $a5 = "Es gibt noch weitere moeglichkeiten Bitcoin zu erwerben" fullword ascii
      
  condition: 
    uint16(0) == 0x5a4d and filesize < 1000KB and 3 of ($a*)
}
