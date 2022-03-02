rule APT_Kimsuky_Aug_2020_1 {
   meta:
      description = "Detect Gold Dragon used by Kimsuky APT group"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2020-08-31"
      hash1 = "4ff2a67b094bcc56df1aec016191465be4e7de348360fd307d1929dc9cbab39f"
      hash2 = "97935fb0b5545a44e136ee07df38e9ad4f151c81f5753de4b59a92265ac14448"
   strings:
      $s1 = "/c systeminfo >> %s" fullword ascii
      $s2 = "/c dir %s\\ >> %s" fullword ascii
      $s3 = ".?AVGen3@@" fullword ascii
      $s4 = { 48 6f 73 74 3a 20 25 73 0d 0a 52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 25 73 25 73 0d 0a 25 73 0d 0a 25 73 } //Host: %s\r\nReferer: http://%s%s\r\n%s\r\n%s
      $s5 = "%s?filename=%s" fullword ascii
      $s6 = "Content-Disposition: form-data; name=\"userfile\"; filename=\"" fullword ascii
      $s7 = "Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywhpFxMBe19cSjFnG" fullword ascii
      $s8 = "Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"" fullword ascii
      $s9 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; .NET CLR 1.1.4322)" fullword ascii
      $s10 = "\\Microsoft\\HNC" fullword ascii
      $s11 = "Mozilla/5.0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 150KB and 8 of them
}
