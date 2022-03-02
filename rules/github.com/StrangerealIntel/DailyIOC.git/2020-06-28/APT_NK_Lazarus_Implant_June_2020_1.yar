import "pe"

rule APT_NK_Lazarus_Implant_June_2020_1 {
   meta:
      description = "Detect Lazarus implant June 2020"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/ccxsaber/status/1277064824434745345"
      date = "2020-06-28"
      hash1 = "21afaceee5fab15948a5a724222c948ad17cad181bf514a680267abcce186831"
   strings:
      $s1 = "Upgrade.exe" fullword ascii /* Based pattern on samples */
      $s2 = "ver=%d&timestamp=%lu" fullword ascii
      $s3 = "_update.php" fullword ascii /* Based pattern on URL C2 */
      $s4 = "Dorusio Wallet 2.1.0 (Check Update Windows)" fullword wide
      $s5 = "Content-Type: application/x-www-form-urlencoded" fullword ascii
      $s6 = "CONOUT$" fullword ascii
      $s7 = "D$8fD;i" fullword ascii /* Lazarus gems*/
      $s8 = "WinHttpOpenRequest" fullword ascii
      $s9 = "HTTP/1.0" fullword ascii
      $s10 = "POST" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and ( pe.imphash() == "565005404f00b7def4499142ade5e3dd" or 6 of them )
}
