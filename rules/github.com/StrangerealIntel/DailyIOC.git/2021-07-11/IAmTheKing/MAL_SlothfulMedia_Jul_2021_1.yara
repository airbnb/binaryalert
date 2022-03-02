rule MAL_SlothfulMedia_Jul_2021_1 {
   meta:
        description = "Detect SlothfulMedia malware"
        author = "Arkbird_SOLG"
        reference = "hhttps://us-cert.cisa.gov/ncas/analysis-reports/ar20-275a"
        date = "2021-07-09"
        hash1 = "04ca010f4c8997a023fabacae230698290e3ff918a86703c5e0a2a6983b039eb"
        hash2 = "927d945476191a3523884f4c0784fb71c16b7738bd7f2abd1e3a198af403f0ae"
        hash3 = "ed5258306c06d6fac9b13c99c7c8accc7f7fa0de4cf4de4f7d9eccad916555f5"
        tlp = "White"
        adversary = "IAmTheKing"
   strings:
        $s1 = { 5c 00 53 00 74 00 72 00 69 00 6e 00 67 00 46 00 69 00 6c 00 65 00 49 00 6e 00 66 00 6f 00 5c 00 25 00 30 00 34 00 78 00 25 00 30 00 34 00 78 00 5c 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e }
        $s2 = "\\VarFileInfo\\Translation" fullword wide 
        $s3 = { 5c 00 46 00 69 00 6c 00 74 00 65 00 72 00 [2-8] 2e 00 6a 00 70 00 67 }
        $s4 = "\\SetupUi" fullword wide
        $s5 = { 25 00 73 00 7c 00 25 00 73 00 7c 00 25 00 73 00 7c 00 25 00 73 }
        $s6 = { 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 25 00 73 00 25 00 64 }
        $s7 = { 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 25 64 }
        $s8 = { 45 00 72 00 61 00 20 00 75 00 70 00 6c 00 6f 00 61 00 64 00 3a 00 25 00 73 00 20 00 25 00 64 }
        $s9 = "ExtKeyloggerStart" fullword ascii 
        $s10 = "ExtKeyloggerStop" fullword ascii 
        $s11 = "ExtServiceDelete" fullword ascii 
   condition:
     uint16(0) == 0x5a4d and filesize > 20KB and 8 of ($s*)
}
