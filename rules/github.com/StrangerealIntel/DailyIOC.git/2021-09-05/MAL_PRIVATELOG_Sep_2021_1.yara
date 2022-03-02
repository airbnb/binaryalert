rule MAL_PRIVATELOG_Sep_2021_1 {
   meta:
        description = "Detect PRIVATELOG malware"
        author = "Arkbird_SOLG"
        reference = "https://www.fireeye.com/blog/threat-research/2021/09/unknown-actor-using-clfs-log-files-for-stealth.html"
        date = "2021-09-01"
        hash1 = "1e53559e6be1f941df1a1508bba5bb9763aedba23f946294ce5d92646877b40c"
        hash2 = "b9d4ec771a79f53a330b29ed17f719dac81a4bfe11caf0eac0efacd19d14d090"
        // created from the same builder
        level = "experimental"
        tlp = "White"
        adversary = "-"
   strings:
        $s1 = { 41 89 d0 48 83 ec 20 4c 89 f1 31 d2 e8 cb 8c 00 00 48 83 ec 10 48 89 5c 24 20 48 8d 15 4b 03 02 00 48 c7 c1 02 00 00 80 45 31 c0 41 b9 19 01 02 00 ff 15 55 52 01 00 48 83 c4 30 89 c7 85 c0 75 5a 49 8d 46 02 48 8b 0b 48 83 ec 30 48 89 74 24 28 48 89 44 24 20 48 8d 15 4f 03 02 00 45 31 c0 45 31 c9 ff 15 1b 52 01 00 48 83 c4 30 89 c7 85 c0 75 28 66 41 c7 06 7b 00 48 83 ec 20 48 8d 15 c0 02 02 00 4c 89 f1 ff 15 17 52 01 00 4c 89 f1 e8 67 c9 00 00 48 83 c4 20 31 ff 48 8b 0b 48 83 ec 20 ff 15 d4 51 01 00 48 83 c4 20 48 8b 4d f8 48 31 e9 48 83 ec 20 e8 f0 79 00 00 48 83 c4 20 89 f8 48 89 ec }
        $s2 = { 48 8d 0d 87 c9 01 00 48 8d 15 47 01 00 00 ff 15 1a 14 01 00 48 89 05 e3 d8 01 00 48 85 c0 0f 84 d0 00 00 00 c7 05 e8 d8 01 00 00 00 00 00 48 8d 15 d1 d8 01 00 c7 05 df d8 01 00 b8 0b 00 00 0f 28 05 80 1c 01 00 0f 29 05 b9 d8 01 00 44 8b 05 e2 c8 01 00 41 8d 48 01 89 0d d8 c8 01 00 44 89 05 b5 d8 01 00 48 89 c1 ff 15 b8 13 01 00 31 c9 ba 01 00 00 00 45 31 c0 45 31 c9 ff 15 b5 14 01 00 48 89 05 9e d8 01 00 48 85 c0 0f 84 85 00 00 00 48 b8 04 00 00 00 01 00 00 00 48 89 05 68 d8 01 00 48 8d 15 5d d8 01 00 c7 05 5f d8 01 00 00 00 00 00 48 c7 05 5c d8 01 00 00 00 00 00 48 8b 0d 39 d8 01 00 ff 15 5b 13 01 00 e8 61 01 00 00 85 c0 74 2b 48 b9 01 00 00 00 01 00 00 00 48 89 0d 25 d8 01 00 48 8d 15 1a d8 01 00 89 05 20 d8 01 00 eb 44 48 83 c4 28 48 ff 25 57 14 01 00 48 8b 0d 20 d8 01 00 ba ff ff ff ff ff 15 9d 13 01 00 e8 eb c5 ff ff 48 b8 01 00 00 00 01 00 00 00 48 89 05 e3 d7 01 00 48 8d 15 d8 d7 01 00 c7 05 da d7 01 00 00 00 00 00 48 c7 05 d7 d7 01 00 00 00 00 00 48 8b 0d b4 d7 01 00 48 83 c4 28 48 ff 25 d1 12 01 00 48 83 ec 28 83 f9 01 75 69 48 b8 03 00 00 00 01 00 00 00 48 89 05 9b d7 01 00 48 8d 15 90 d7 01 00 31 c0 89 05 94 d7 01 00 89 05 9a d7 01 00 8b 05 ac c7 01 00 8d 48 01 89 0d a3 c7 01 00 89 05 81 d7 01 00 48 8b 0d 5e d7 01 00 ff 15 80 12 01 }
        $s3 = { 48 89 01 c7 44 24 28 00 00 00 00 c7 44 24 20 03 00 00 00 ba 00 00 00 80 41 b8 01 00 00 00 45 31 c9 ff 15 f7 59 01 00 48 83 f8 ff 0f 84 e0 01 00 00 48 89 c6 0f 57 c0 48 8d 94 24 a0 00 00 00 0f 29 42 60 0f 29 42 50 0f 29 42 40 0f 29 42 30 0f 29 42 20 0f 29 42 10 0f 29 02 48 c7 42 70 00 00 00 00 4c 8d 44 24 7c 41 c7 00 78 00 00 00 48 89 c1 ff 15 9f 59 01 00 85 c0 0f 84 d0 01 00 00 8b 84 24 dc 00 00 00 c1 e0 0d 48 8d 8c 24 98 00 00 00 48 89 4c 24 38 89 44 24 20 c7 44 24 30 01 00 00 00 c7 44 24 28 02 00 00 00 48 89 f1 31 d2 45 31 c0 45 31 c9 ff 15 53 59 01 00 85 }
        $s4 = { c6 00 00 48 ff c0 48 83 ec 20 48 89 f9 48 89 c2 ff 15 8e 19 01 00 48 8d 15 a9 cd 01 00 48 89 d9 ff 15 86 19 01 00 48 89 d9 ff 15 55 19 01 00 48 }
        $s5 = "Global\\APCI#" fullword wide
        $s6 = "uGlobal\\HVID_" fullword ascii
   condition:
    uint16(0) == 0x5A4D and filesize > 20KB and 4 of ($s*)
}
