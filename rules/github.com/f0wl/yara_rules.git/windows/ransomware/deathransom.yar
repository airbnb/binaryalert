rule Deathransom : ransomware {
   meta:
    description = "Detects Deathransom Ransomware" 
    author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
    reference = "https://dissectingmalwa.re/quick-and-painless-reversing-deathransom-wacatac.html"
    date = "2019-11-20"
    hash1 = "7c2dbad516d18d2c1c21ecc5792bc232f7b34dadc1bc19e967190d79174131d1"
      
   strings:
    $s1 = "https://localbitcoins.com/buy_bitcoins" fullword ascii
    $s2 = "read_me.txt" fullword wide
    $s3 = "$recycle.bin" fullword wide
    $s4 = "bootsect.bak" fullword wide
    $s5 = "files are encrypted." fullword ascii
    $s6 = "select * from Win32_ShadowCopy" fullword wide
    $s7 = "To be sure we have the decryptor and it works you can send an" fullword ascii
    $s8 = "All your files, documents, photos, databases and other important" fullword ascii
    $s9 = "Win32_ShadowCopy.ID='%s'" fullword wide
    $s10 = "email death@firemail.cc  and decrypt one file for free. But this" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      5 of them
} 
