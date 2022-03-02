rule Ran_OnyxLocker_Nov_2020_1 {
   meta:
      description = "Detect OnyxLocker ransomware"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Kangxiaopao/status/1328614320016560128"
      date = "2020-11-18"
      hash1 = "7e3c97d3d274b5f7fedad6e392e6576ac3e5724ddd7e48c58a654b6b95eb40d7"
   strings:
      $s1 = "IEncryptionProvider" fullword ascii
      $s2 = "OnyxLocker.exe" fullword wide
      $s3 = "GetEncryptionThreads" fullword ascii
      $s4 = "CreateEncryptionKey" fullword ascii
      $s5 = ".NETFramework,Version=v4.5.2" fullword ascii
      $s6 = "get_TargetFiles" fullword ascii
      $s7 = "IsTargetFile" fullword ascii
      $s8 = "<TargetFiles>k__BackingField" fullword ascii
      $s9 = "XxteaEncryptionProvider" fullword ascii
      $s10 = "GetStartingFolders" fullword ascii
      $s11 = "<EncryptionKey>k__BackingField" fullword ascii
      $s12 = "RECOVERY INSTRUCTIONS" fullword wide
      $s13 = "$182eaa96-fcb2-458b-85cb-a9b8da57ae71" fullword ascii
      $s14 = ".NET Framework 4.5.2" fullword ascii
      $s15 = "TraverseDirectories" fullword ascii
      $s16 = "{0} {1}" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize > 8KB and 8 of them
}
