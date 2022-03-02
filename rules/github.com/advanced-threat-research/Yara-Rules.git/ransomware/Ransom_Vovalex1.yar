import "pe"

rule ransom_vovalex_part2{
   meta:
      description = "Vovalex ransomware detection part 2"
      author = "CB @ ATR"
      date = "2021-02-01"
      malware_type = "Ransom"
      malware_family = "Ransom:Win/Vovalex"
      hash1 = "0604acc15196120db2f4ca922feb2a4c858a46123cb26e9af2ef97b4c7839121"
      hash2 = "fe9ff27ec0a1a48cbb8bc043f260a656c221c6c61704187a390bc8da6f91103a"
      hash3 = "3b198c367aca1d239abc48bdeb8caabf9b8f2b630071b8e0fd1e86940eab14d6"

   strings:
      $x1 = "If you don't know where to buy Monero - visit these websites: https://www.bestchange.ru/ https://www.bestchange.com" fullword ascii
      $s2 = "Full list: https://www.getmonero.org/community/merchants/#exchanges" fullword ascii
      $s3 = ": https://www.getmonero.org/community/merchants/#exchanges" fullword ascii
      $s4 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\file.d" fullword ascii
      $s5 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\utf.d" fullword ascii
      $s6 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\stdio.d" fullword ascii
      $s7 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\format.d" fullword ascii
      $s8 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\random.d" fullword ascii
      $s9 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\conv.d" fullword ascii
      $s10 = "3. If everything is good, you will receive the decryptor." fullword ascii
      $s11 = "Attempting to flush() in an unopened file" fullword ascii
      $s12 = "Monero: 4B45W7V1sJAZBnPSnvcipa5k7BRyC4w8GCTfQCUL2XRx5CFzG3iJtEk2kqEvFbF7FagEafRYFfQ6FJnZmep5TsnrSfxpMkS" fullword ascii
      $s13 = "..\\AppData\\Local\\dub\\packages\\crypto-0.2.16\\crypto\\src\\crypto\\padding.d" fullword ascii
      $s14 = "crypto.aes.AES!(4u, 8u, 14u).AES" fullword ascii
      $s15 = "..\\AppData\\Local\\dub\\packages\\crypto-0.2.16\\crypto\\src\\crypto\\aes.d" fullword ascii
      $s16 = "Monero - " fullword ascii
      $s17 = "std.random.uniform(): invalid bounding interval " fullword ascii
      $s18 = "crypto.aes.AESUtils" fullword ascii
      $s19 = "2. Send us a mail with proofs of transaction: VovanAndLexus@cock.li" fullword ascii
      $s20 = "crypto.aes" fullword ascii

      $op0 = { 48 8d 8d 10 ff ff ff e8 4a 22 fe ff f7 df 89 bd }
      $op1 = { e8 60 6e fb ff 34 01 75 d6 4c 8b 46 40 48 8b 56 }
      $op2 = { 4c 8d 85 40 ff ff ff 4c 8d 15 d2 78 02 00 4c 89 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 1 of ($x*) and 4 of them ) and all of ($op*)
      ) or ( all of them )
}