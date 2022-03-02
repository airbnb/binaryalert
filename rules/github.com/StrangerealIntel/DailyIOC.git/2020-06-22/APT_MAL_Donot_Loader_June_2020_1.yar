import "pe"

rule APT_MAL_Donot_Loader_June_2020_1 {
   meta:
      description = "Detect loader malware used by APT Donot for drops the final stage"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/ccxsaber/status/1274978583463649281"
      date = "2020-06-22"
      hash1 = "1ff33d1c630db0a0b8b27423f32d15cc9ef867349ac71840aed47c90c526bb6b"
   strings:
      $s1 = "C:\\Users\\spartan\\Documents\\Visual Studio 2010\\new projects\\frontend\\Release\\test.pdb" fullword ascii
      $s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36 Edg/81.0.416.68" fullword ascii
      $s3 = "bbLorkybbYngxkjbb]khbbmgvjgz4k~k" fullword ascii
      $s4 = "8&8-8X8.959?9Q9h9v9|9" fullword ascii
      $s5 = "0$0h4h5l5p5t5x5|5" fullword ascii
      $s6 = "?&?+?1?7?M?T?g?z?" fullword ascii
      $s7 = "12.02.1245" fullword ascii
      $s8 = ">>?C?L?[?~?" fullword ascii
      $s9 = "6*6=6P6b6" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and 7 of them 
}
