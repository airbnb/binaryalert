rule Mal_PhantomNet_Nov_2020_1 {
   meta:
      description = "Detect PhantomNet (November 2020)"
      author = "Arkbird_SOLG"
      reference = "https://insight-jp.nttsecurity.com/post/102glv5/pandas-new-arsenal-part-3-smanager"
      date = "2020-12-19"
      hash1 = "ea7b2def3335b81048aac8fc372349f38453b676fa833603b7e15c45437f6858"
      hash2 = "338502691f6861ae54e651a25a08e62eeca9febc6830978a670d44caf3d5d056"
   strings:
      $s1 = { 25 73 25 30 38 58 } // %s%08X
      $s2 = { 68 00 74 00 74 00 70 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 } // http\\shell\\open\\command
      $s3 = { 6b 25 34 64 2d 25 30 32 64 2d 25 30 32 64 } // k%4d-%02d-%02d
      $s4 = { 47 6c 6f 62 61 6c 5c 47 6c 6f 62 61 6c 41 63 70 72 6f 74 65 63 74 4d 75 74 65 78 } // Global\\GlobalAcprotectMutex
      $s5 = "Proxy-Authorization: NTLM" fullword ascii
      $s6 = { 50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 6b 65 65 70 2d 61 6c 69 76 65 0d 0a } // Proxy-Connection: keep-alive\r\n
      $s7 = { 48 54 54 50 2f 31 2e 31 20 00 00 00 48 54 54 50 2f 31 2e 30 20 } // HTTP config
      $s8 = { 52 00 6f 00 6f 00 74 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00 32 00 00 00 00 00 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 00 00 57 51 4c } // WQL AV detection 
      $s9 = { 68 74 74 70 00 00 00 00 25 5b 5e 3a 5d 00 00 00 25 2a 5b 5e 3a 5d 3a 25 64 } // config
      $s10 = { 48 6f 73 74 3a 20 } // Host: 
      $s11 = { 43 6f 6f 6b 69 65 73 3a 20 } // Cookies: 
      $s12 = "Proxy-Authenticate: NTLM" fullword ascii
    condition:
      uint16(0) == 0x5a4d and filesize > 90KB and 9 of them 
}
