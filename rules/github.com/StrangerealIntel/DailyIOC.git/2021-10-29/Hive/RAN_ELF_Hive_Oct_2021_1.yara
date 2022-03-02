rule RAN_ELF_Hive_Oct_2021_1 {
   meta:
        description = "Detect ELF version of Hive ransomware"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/ESETresearch/status/1454100591261667329"
        date = "2021-10-29"
        hash1 = "6a0449a0b92dc1b17da219492487de824e86a25284f21e6e3af056fe3f4c4ec0"
        hash2 = "bdf3d5f4f1b7c90dfc526340e917da9e188f04238e772049b2a97b4f88f711e3"
        tlp = "white"
        adversary = "-"
        level = "experimental"
   strings:
        $s1 = { 49 3b 66 10 76 ?? 48 83 ec ?? 48 89 6c 24 ?? 48 8d 6c 24 ?? 48 8b [3] 48 }
        $s2 = { 48 89 f8 48 89 f3 48 83 ec 27 48 83 e4 f0 48 89 44 24 10 48 89 5c 24 18 48 8d 3d 41 [2] 00 48 8d 9c 24 68 00 ff ff 48 89 5f 10 48 89 5f 18 48 89 1f 48 89 67 08 b8 00 00 00 00 0f a2 89 c6 83 f8 00 74 33 81 fb 47 65 6e 75 75 1e 81 fa 69 6e 65 49 75 16 81 f9 6e 74 65 6c 75 0e c6 05 [3] 00 01 c6 05 [3] 00 01 b8 01 00 00 00 0f a2 89 05 [3] 00 48 8b 05 }
        $s3 = { 66 0f 38 dc ?? 66 0f 38 dc ?? 66 0f 38 dc ?? 66 0f 38 dc ?? 66 0f 38 dc ?? 66 0f 38 dc }
        $s4 = { 00 00 48 8b ac 24 68 02 00 00 48 81 c4 70 02 00 00 c3 ?? 80 ?? 0e [6] 48 8b [2] 48 }
   condition:
        uint32(0) == 0x464C457F and filesize > 20KB and all of ($s*) 
}
