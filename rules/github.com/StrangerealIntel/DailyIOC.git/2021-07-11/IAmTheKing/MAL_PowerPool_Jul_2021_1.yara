rule MAL_PowerPool_Jul_2021_1 {
   meta:
        // also called KingOfHearts JSON C++ implant
        description = "Detect PowerPool malware"
        author = "Arkbird_SOLG"
        reference = "https://securelist.com/iamtheking-and-the-slothfulmedia-malware-family/99000/"
        date = "2021-07-09"
        // Build 2019
        hash1 = "9c08136b26ee5234c61a5d9e5a17afb15da35efc66514d2df5b53178693644c5"
        // Build 2018
        hash2 = "23e7e0bbc36d523daa8e3cd8e32618c6c1fb61e32f664756e77d7917b3b11644"
        // Build  2017
        hash3 = "e30d32cc40ad19add7dfdcbed960d5f074ea632b796ae975b75eb25455b66bb0"
        //Build 2016
        hash4 = "88e7813340194acc4b094fd48ecf665a12d19245b90f2a69dab5861982ca95f6"
        tlp = "White"
        adversary = "IAmTheKing"
   strings:
        $s1 = "write info fail!!! GetLastError-->%u" fullword ascii
        $s2 = "Set Option failed errcode: %ld" fullword ascii
        $s3 = { 68 96 00 00 00 68 ?? c4 44 00 b9 ?? 4c 45 00 e8 [2] fb ff 68 [2] 44 00 e8 ?? 4f fe ff 59 c3 68 96 00 00 00 68 ?? c5 44 00 b9 ?? 4c 45 00 e8 [2] fb ff 68 [2] 44 00 e8 ?? 4f fe ff 59 c3 68 96 00 00 00 68 [2] 44 00 b9 ?? 4c 45 00 e8 [2] fb ff 68 [2] 44 00 e8 [2] fe ff 59 c3 83 3d ?? 4c 45 00 00 74 38 53 6a 01 b8 ?? 4c 45 00 e8 ?? a0 fc ff 50 6a 00 b9 ?? 4c 45 00 e8 [2] fb ff 6a ff bb 01 00 00 00 b8 ?? 4c 45 00 e8 [2] fc ff 40 50 b9 ?? 4c 45 00 e8 [2] fb ff 5b 33 c0 6a ff 50 68 ?? 4c 45 00 }
        $s4 = { 2d 2d 25 73 0d 0a 43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 25 73 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 25 73 22 }
        $s5 = { 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69 70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 3b 20 62 6f 75 6e 64 61 72 79 3d 2d 2d 4d 55 4c 54 49 2d 50 41 52 54 53 2d 46 4f 52 4d 2d 44 41 54 41 2d 42 4f 55 4e 44 41 52 59 0d 0a }
        $s6 = { 43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 25 73 22 0d 0a 0d 0a }
        $s7 = { 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 0d 0a }
        $s8 = { 25 73 3b 74 79 70 65 3d 25 73 3b 6c 65 6e 67 74 68 3d 25 73 3b 72 65 61 6c 64 61 74 61 3d 25 73 65 6e 64 }
   condition:
     uint16(0) == 0x5a4d and filesize > 100KB and 6 of ($s*)
}
