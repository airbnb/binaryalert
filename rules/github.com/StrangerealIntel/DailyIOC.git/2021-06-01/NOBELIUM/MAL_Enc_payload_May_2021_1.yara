rule MAL_Enc_payload_May_2021_1 {
   meta:
        description = "Detect encrypted payload, must be with others APT29 rules maybe give lot fake postives due to the pdf header"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-05-28"
        hash1 = "23e20d630a8fd12600c2811d8f179f0e408dcb3e82600456db74cbf93a66e70f"
        hash2 = "656384c4e5f9fe435d51edf910e7ba28b5c6d183587cf3e8f75fb2d798a01eeb"
        level = "Experimental"
        tlp = "White"
        adversary = "NOBELIUM"
   strings:      
        $s1 = { 25 50 44 46 2d 31 2e 33 0a 25 06 8b c4 1c c5 86 66 f3 dc 75 f9 3b dd 8c 44 e3 d3 a4 74 9d 94 4e 2e 0f d9 01 a6 f2 88 6a a8 0b 16 1b 1a fc 60 3f 72 7a 1b c1 a7 bb 2f 19 31 6d 6f 79 db 20 f6 c7 fa e7 eb b9 88 77 de 1f a1 92 d7 ea 68 a9 b7 89 17 92 e8 b2 bb a5 58 56 b4 30 60 f8 28 0c 54 7b 2b 68 ba 7e 01 01 6d ad 2e 6d 72 67 1e b0 a8 ea 42 82 bd 14 9a 86 f0 0d 9a 8b 92 76 b3 b3 7d ef 69 24 2c 9f c2 ca e9 c9 b3 }
        $s2 = { 25 25 45 4f 46 0a }
   condition:
        filesize > 50KB and all of ($s*)
}



