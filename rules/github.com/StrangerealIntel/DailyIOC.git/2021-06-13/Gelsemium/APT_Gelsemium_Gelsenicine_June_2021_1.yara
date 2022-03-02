rule APT_Gelsemium_Gelsenicine_June_2021_1 {
   meta:
        description = "Detect Gelsenicine malware (Loader - Variant 1)"
        author = "Arkbird_SOLG"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2021/06/eset_gelsemium.pdf"
        date = "2021-06-12"
        hash1 = "97982e098a4538d05e78c172c9bbc5b412754df86dc73e760004f0038ec928fb"
        hash2 = "46338cae732ee1664aac77d9dce57c4ff8666460c1a51bee49cae44c86e42df9"
        hash3 = "f0d23aa026ae6ba96051401dc2b390ba5c968d55c2a4b31a36e45fb67dfc2e3c"
        tlp = "white"
        adversary = "Gelsemium"
   strings:      
            $s1 = { b8 [3] 74 e8 [2] 00 00 81 ec bc 03 00 00 53 56 57 be [3] 74 8d bd 38 fc ff ff 6a 1b a5 a5 a5 a5 66 a5 59 33 c0 8d bd 4a fc ff ff be [3] 74 f3 ab 66 ab 8d bd b8 fc ff ff 6a 1c a5 a5 a5 a5 59 33 c0 8d bd c8 fc ff ff 6a 07 f3 ab 59 be [3] 74 8d bd 38 fd ff ff 6a 18 f3 a5 66 a5 8b 5d 0c 59 8d bd 56 fd ff ff 83 65 cc 00 f3 ab 66 ab 8a 03 6a 00 8d 4d e0 c7 45 c0 24 00 00 00 c7 45 c4 25 00 00 00 c7 45 c8 23 00 00 00 88 45 e0 ff 15 [3] 74 a1 [3] 74 8d 4d e0 ff 30 6a 00 53 ff 15 [3] 74 8a 45 0f 6a 00 8d 4d d0 c7 45 fc 01 00 00 00 88 45 d0 ff 15 [3] 74 8b 35 [3] 74 bf [3] 74 57 ff d6 59 50 57 8d 4d d0 ff 15 [3] 74 8b 55 d4 8b 0d [3] 74 85 d2 c6 45 fc 02 75 02 8b d1 8b 43 04 85 c0 75 02 8b c1 ff 75 d8 52 50 ff 15 [3] 74 83 c4 0c 85 c0 0f 85 d9 00 00 00 8d 85 b8 fd ff ff 50 68 04 01 00 00 ff 15 [3] 74 8d 85 b8 fd ff ff 50 ff d6 85 c0 59 0f 84 b5 00 00 00 8d 85 b8 fd ff ff 50 ff d6 66 83 bc 45 b6 fd ff ff 2f 59 74 56 8d 85 b8 fd ff ff 50 ff d6 66 83 bc 45 b6 fd ff ff 5c 59 74 41 8d 4d e0 ff 15 [3] 74 8b 7d e4 8b 5d d8 8d 4d e0 ff 15 [3] 74 8b 45 e4 89 45 f0 8d 85 b8 fd ff ff 50 ff d6 59 8d 84 45 b8 fd ff ff 50 8d 85 b8 fd ff ff 50 8d 44 5f fe 50 ff }
            $s2 = { ff 75 0c 89 45 f0 ff d6 50 ff 75 0c ff 75 f0 ff 15 [3] 74 83 c4 10 85 c0 }
            $s3 = "pluginkey" fullword wide
            $s4 = { 55 8b ec 51 33 c0 56 f6 05 [3] 74 01 89 45 fc 0f 85 c6 00 00 00 8a 4d 0b 80 0d [3] 74 01 53 bb [3] 74 57 88 0d [3] 74 50 8b cb ff 15 [3] 74 8b 35 [3] 74 bf [3] 74 57 ff d6 59 50 57 8b cb ff 15 [3] 74 8a 45 0b bb [3] 74 6a 00 8b cb a2 [3] 74 ff 15 [3] 74 bf [3] 74 57 ff d6 59 50 57 8b cb ff 15 [3] 74 8a 45 0b bb [3] 74 6a 00 8b cb a2 [3] 74 ff 15 [3] 74 bf [3] 74 57 ff d6 59 50 57 8b cb ff 15 [3] 74 8a 45 0b bb [3] 74 6a 00 8b cb a2 [3] 74 ff 15 [3] 74 bf [3] 74 57 ff d6 59 50 57 8b cb ff 15 [3] 74 68 [2] e2 74 e8 [2] 00 00 59 5f 33 c0 5b 8b 75 08 8a 4d 0b 68 [3] 74 68 [3] 74 88 0e 50 8b ce 89 46 04 89 46 08 89 46 0c e8 [2] 00 00 8b c6 5e }
    condition:
            uint16(0) == 0x5a4d and filesize > 15KB and 3 of ($s*) 
}
