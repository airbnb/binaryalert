rule Mal_FunnyDream_Backdoor_Nov_2020_1 {
   meta:
      description = "Detect backdoor used by FunnyDream (November 2020)"
      author = "Arkbird_SOLG"
      reference = "https://insight-jp.nttsecurity.com/post/102glv5/pandas-new-arsenal-part-3-smanager"
      date = "2020-12-19"
      hash1 = "ce5c8741bffa8de5093d1831d736a7e478a54baa3676da37cde24f38d10f3529"
   strings:
      $s1 = { 25 64 25 64 25 64 20 25 64 3a 25 64 } // %d%d%d %d:%d
      $s2 = { 73 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 00 00 50 72 6f 78 79 45 6e 61 62 6c 65 00 50 72 6f 78 79 53 65 72 76 65 } // Enable Proxy
      $s3 = { 48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } // HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0
      $s4 = { 48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d 0a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 25 75 0d 0a 53 65 74 2d 43 6f 6f 6b 69 65 3a 20 25 75 25 73 25 73 0d 0a 53 65 72 76 65 72 3a 20 53 69 6d 70 6c 65 0d 0a 43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6e 6f 2d 73 74 6f 72 65 0d 0a 50 72 61 67 6d 61 3a 20 6e 6f 2d 63 61 63 68 65 } // config request
      $s5 = { 43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 2f 31 2e 30 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 31 30 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 29 0d 0a 50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 0d 0a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 30 0d 0a 48 6f 73 74 3a 20 25 73 0d 0a 50 72 61 67 6d 61 3a 20 6e 6f 2d 63 61 63 68 65 0d 0a 0d 0a } // CONNECT %s:%d HTTP/1.0\r\nUser-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1;)\r\nProxy-Connection: Keep-Alive\r\nContent-Length: 0\r\nHost: %s\r\nPragma: no-cache\r\n\r\n
      // Doesn't count in the condition
      $s6 = { 31 32 33 34 35 36 00 00 55 73 65 72 2d 30 30 31 } // Creds : 123456\x00\x00User-001
      $s7 = { 25 73 20 25 73 25 73 2f 25 73 2f 25 30 38 58 25 30 38 58 2f 25 75 2f 25 75 2f 25 75 2f 25 75 2f 25 75 2f 25 75 2f 25 30 38 58 25 30 38 78 } // %s %s%s/%s/%08X%08X/%u/%u/%u/%u/%u/%u/%08X%08x
      $s8 = { 63 6c 74 2e 65 78 65 00 44 6c 6c 49 6e 73 74 61 6c 6c 00 53 74 61 72 74 } // clt.exe\x00DllInstall\x00Start
      $s9 = { 32 30 30 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 65 73 74 61 62 6c 69 73 68 65 64 } // 200 Connection established
      $s10 = { 5c 63 6d 64 c7 85 e0 fe ff ff 2e 65 78 65 } 
    condition:
      uint16(0) == 0x5a4d and filesize > 90KB and 6 of them 
}
