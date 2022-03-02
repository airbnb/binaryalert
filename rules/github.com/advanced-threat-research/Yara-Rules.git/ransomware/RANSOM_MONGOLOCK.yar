rule ransom_monglock {
   
   meta:

      description = "Ransomware encrypting Mongo Databases "
      author = "Christiaan Beek - McAfee ATR team"
      date = "2019-04-25"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/MongLock"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash5 = "c4de2d485ec862b308d00face6b98a7801ce4329a8fc10c63cf695af537194a8"

   strings:

      $x1 = "C:\\Windows\\system32\\cmd.exe" fullword wide
      $s1 = "and a Proof of Payment together will be ignored. We will drop the backup after 24 hours. You are welcome! " fullword ascii
      $s2 = "Your File and DataBase is downloaded and backed up on our secured servers. To recover your lost data : Send 0.1 BTC to our BitCoin" ascii
      $s3 = "No valid port number in connect to host string (%s)" fullword ascii
      $s4 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii
      $s5 = "# https://curl.haxx.se/docs/http-cookies.html" fullword ascii
      $s6 = "Connection closure while negotiating auth (HTTP 1.0?)" fullword ascii
      $s7 = "detail may be available in the Windows System event log." fullword ascii
      $s8 = "Found bundle for host %s: %p [%s]" fullword ascii
      $s9 = "No valid port number in proxy string (%s)" fullword ascii


      $op0 = { 50 8d 85 78 f6 ff ff 50 ff b5 70 f6 ff ff ff 15 }
      $op1 = { 83 fb 01 75 45 83 7e 14 08 72 34 8b 0e 66 8b 45 }
      $op2 = { c7 41 0c df ff ff ff c7 41 10 }

   condition:
      ( uint16(0) == 0x5a4d and
      filesize < 2000KB and
      ( 1 of ($x*) and
      4 of them ) and
      all of ($op*)
      ) or
      ( all of them )
}

