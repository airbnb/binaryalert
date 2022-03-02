rule RAN_ELK_DarkRadiation_Jul_2021_3 {
   meta:
        description = "Detect structures of scripts like used by the DarkRadiation ransomware"
        author = "Arkbird_SOLG"
        reference1 = "https://twitter.com/Amigo_A_/status/1409212416802574337"
        reference2 = "https://bazaar.abuse.ch/browse/tag/DarkRadiation/"
        hash1 = "bc6e4b879228c248b7ff9aebbf857e94354829a98b6aea9b1c187005cbc2e0d0"
        hash2 = "691afd4ef5f33d99053c57456ce9fa126e29d51d4dd510928193d8c3332547b1"
        hash3 = "fdd8c27495fbaa855603df4f774fe86bbc21743f59fd039f734feb07704805bd"
        date = "2021-07-03"
        tlp = "White"
        adversary = "FERRUM"
    strings:
        $s1 = { 66 6f 72 20 66 69 6c 65 20 69 6e 20 60 66 69 6e 64 20 2f 20 2d 6e 61 6d 65 20 27 2a 2e 73 68 27 20 2d 74 79 70 65 20 66 20 2d 65 78 65 63 20 67 72 65 70 20 2d 6c }
        $s2 = { 72 6d 20 2d 72 66 20 2f 76 61 72 2f 6c 6f 67 2f 79 75 6d 2a }
        $s3 = { 69 66 20 72 70 6d 20 2d 71 20 6f 70 65 6e 73 73 6c }
        $s4 = { 6f 70 65 6e 73 73 6c 20 65 6e 63 20 2d 61 65 73 2d 32 35 36 2d 63 62 63 20 2d 73 61 6c 74 20 2d 70 61 73 73 20 70 61 73 73 3a 24 50 41 53 53 20 2d 69 6e 20 24 66 69 6c 65 20 2d 6f 75 74 20 24 66 69 6c 65 2e e2 98 a2 }
        $x1 = { 55 52 4c 3d 27 68 74 74 70 73 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 27 24 54 4f 4b 45 4e }
        $x2 = { 4d 53 47 5f 55 52 4c 3d 24 55 52 4c 27 2f 73 65 6e 64 4d 65 73 73 61 67 65 3f 63 68 61 74 5f 69 64 3d 27 }
        $x3 = { 55 50 44 5f 55 52 4c 3d 24 55 52 4c 27 2f 67 65 74 55 70 64 61 74 65 73 3f 6f 66 66 73 65 74 3d 27 }
        $x4 = { 62 61 73 68 20 2d 69 20 3e 26 20 2f 64 65 76 2f 74 63 70 2f 24 49 50 2f 24 50 4f 52 54 20 30 3e 26 31 }
        $x5 = { 6d 73 67 3d 22 5b 2b 5d 20 53 68 65 6c 6c 20 52 75 6e 6e 69 6e 67 2e 22 }
        $x6 = { 72 65 73 3d 24 28 63 75 72 6c 20 2d 73 20 2d 58 20 50 4f 53 54 20 24 4d 53 47 5f 55 52 4c 20 2d 64 20 63 68 61 74 5f 69 64 3d 24 49 44 5f 4d 53 47 20 2d 64 20 74 65 78 74 3d 22 44 4f 4e 45 21 21 21 22 20 26 29 }
        $y1 = { 23 21 2f 62 69 6e 2f 62 61 73 68 }
        $y2 = { 3b [2-5] 3d 27 [2-5] 27 3b [2-5] 3d 27 [2-5] 27 3b [2-5] 3d 27 [2-5] 27 3b [2-5] 3d 27 [2-5] 27 3b }
        $y3 = { 65 76 61 6c 20 22 24 [2-5] 24 [2-5] 24 [2-5] 24 }
    condition:
       filesize > 1KB and ( 3 of ($s*) or 5 of ($x*) or all of ($y*) ) 
} 
