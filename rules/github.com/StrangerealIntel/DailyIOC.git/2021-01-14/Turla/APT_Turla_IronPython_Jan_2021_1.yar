rule APT_Turla_IronPython_Jan_2021_1 {
   meta:
      description = "Detect IronPython loader used by Turla Group"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/DrunkBinary/status/1349759986595995653"
      date = "2021-01-14"
      hash1 = "3aa37559ef282ee3ee67c4a61ce4786e38d5bbe19bdcbeae0ef504d79be752b6"
      hash2 = "8df0c705da0eab20ba977b608f5a19536e53e89b14e4a7863b7fd534bd75fd72"
      hash3 = "b5b4d06e1668d11114b99dbd267cde784d33a3f546993d09ede8b9394d90ebb3"
      hash4 = "b095fd3bd3ed8be178dafe47fc00c5821ea31d3f67d658910610a06a1252f47d"
   strings:
      $lambda = { 3d 6c 61 6d 62 64 61 20 [1-6] 2c [1-6] 3a 27 27 2e 6a 6f 69 6e 28 5b 63 68 72 28 28 6f 72 64 28 [1-6] 29 5e [1-6] 29 25 30 78 [1-4] 29 20 66 6f 72 20 [1-6] 20 69 6e 20 [1-6] 5d 29 0a} // -> =lambda .,.:''.join([chr((ord(.)^.)%0x.) for . in .])
      $lib1 = { 69 6d 70 6f 72 74 20 62 61 73 65 36 34 } // import base64
      $lib2 = { 66 72 6f 6d 20 53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } // from System.Security.Cryptography import*
      $lib3 = { 66 72 6f 6d 20 53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } // from System.Reflection import*
      $shcode = /(\w.){6}.(', \d{1,3}\)){1}/ nocase // \x??\x??\x??', ???)
      $cmd1 = "os.getenv" fullword ascii
      $cmd2 = "except System.SystemException as ex:" fullword ascii
      $cmd3 = ".format(ex.Message,ex.StackTrace))" fullword ascii
      $cmd4 = "return System.Array[System.Byte]([ord(" fullword ascii
   condition:
      filesize > 120KB and $lambda and $shcode and all of ($lib*) and all of ($cmd*)
}
