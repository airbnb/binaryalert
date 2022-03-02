rule Lockbit2_Jul21 {
   meta:
      description = "simple rule to detect latest Lockbit ransomware Jul 2021"
      author = "CB @ ATR"
      date = "2021-07-28"
      version = "v1"
      hash1 = "f32e9fb8b1ea73f0a71f3edaebb7f2b242e72d2a4826d6b2744ad3d830671202"
      hash2 = "dd8fe3966ab4d2d6215c63b3ac7abf4673d9c19f2d9f35a6bf247922c642ec2d"

   strings:
      $seq1 = " /C ping 127.0.0.7 -n 3 > Nul & fsutil file setZeroData offset=0 length=524288 \"%s\" & Del /f /q \"%s\"" fullword wide
      $seq2 = "\"C:\\Windows\\system32\\mshta.exe\" \"%s\"" fullword wide
      $p1 = "C:\\windows\\system32\\%X%X%X.ico" fullword wide
      $p2 = "\\??\\C:\\windows\\system32\\%X%X%X.ico" fullword wide
      $p3 = "\\Registry\\Machine\\Software\\Classes\\Lockbit\\shell\\Open\\Command" fullword wide
      $p4 = "use ToxID: 3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D709C3C4AE9B7" fullword wide
      $p5 = "https://tox.chat/download.html" fullword wide
      $p6 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration" fullword wide
      $p7 = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" fullword wide
      $p8 = "\\LockBit_Ransomware.hta" fullword wide
     
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($seq*) and 4 of them )
      ) or ( all of them )
}
