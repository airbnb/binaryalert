rule Ran_Egregor_Sept_2020_1 {
   meta:
      description = "Detect Egregor ransomware (variant Sept2020)"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-10-07"
      hash1 = "4c9e3ffda0e663217638e6192a093bbc23cd9ebfbdf6d2fc683f331beaee0321"
      hash2 = "aee131ba1bfc4b6fa1961a7336e43d667086ebd2c7ff81029e14b2bf47d9f3a7"
      hash3 = "3fd510a3b2e0b0802d57cd5b1cac1e61797d50a08b87d9b5243becd9e2f7073f"
      hash4 = "9c900078cc6061fb7ba038ee5c065a45112665f214361d433fc3906bf288e0eb"
      hash5 = "a376fd507afe8a1b5d377d18436e5701702109ac9d3e7026d19b65a7d313b332"
   strings:
      $x1 = "dmocx.dll" fullword ascii
      $s2 = "C:\\Logmein\\{888-8888-9999}\\Logmein.log" fullword wide
      $s3 = "M:\\sc\\p\\testbuild.pdb" fullword ascii
      $s4 = "Type Descriptor'" fullword ascii
      $s5 = "=$=`=h=p=t=x=|=" fullword ascii
      $s6 = "--nop" fullword wide
      $s7 = "9,94989@9X9" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 200KB and 1 of ($x*) and 4 of ($s*) 
}
