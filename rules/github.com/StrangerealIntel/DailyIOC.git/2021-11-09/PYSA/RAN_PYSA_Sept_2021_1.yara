rule RAN_PYSA_Sept_2021_1 {
    meta:
        description = "Detect the PYSA ransomware"
        author = "Arkbird_SOLG"
        reference ="Internal Research"
        date = "2021-09-23"
        hash1 = "7c774062bc55e2d0e869d5d69820aa6e3b759454dbc926475b4db6f7f2b6cb14"
        hash2 = "7c774062bc55e2d0e869d5d69820aa6e3b759454dbc926475b4db6f7f2b6cb14"
        hash3 = "44f1def68aef34687bfacf3668e56873f9d603fc6741d5da1209cc55bdc6f1f9"
        tlp = "white"
        adversary = "RAAS"
    strings:
        $s1 = { 57 ff 15 38 a0 45 00 be [2] 45 00 33 ff 56 57 68 01 00 1f 00 ff 15 34 a0 45 00 85 c0 75 2b 56 57 57 ff 15 30 a0 45 00 57 8b f0 e8 44 00 00 00 6a 01 e8 3d 00 00 00 59 59 e8 3f ff ff ff 56 ff 15 2c a0 45 00 }
        $s2 = { 51 a1 34 52 47 00 33 c5 89 45 fc 56 8d 45 f8 50 6a 02 6a 00 68 [2] 45 00 68 02 00 00 80 ff 15 0c a0 45 00 8b 15 bc 50 47 00 8b ca 8d 71 01 8a 01 41 84 c0 75 f9 2b ce 8b 35 08 a0 45 00 8d 41 01 50 52 6a 07 6a 00 68 [2] 45 00 ff 75 f8 ff d6 6a 05 68 [2] 45 00 6a 07 6a 00 68 [2] 45 00 ff 75 f8 ff d6 ff 75 f8 ff 15 10 a0 45 00 8b 4d fc 33 cd 5e e8 [2] 02 00 }
        $s3 = { 57 8d 85 f8 fe ff ff bb 04 01 00 00 50 53 ff 15 48 a0 45 00 8d bd f8 fe ff ff 4f 8a 47 01 47 84 c0 75 f8 be [2] 45 00 8d 85 f4 fd ff ff 53 50 33 db a5 53 a5 66 a5 a4 ff 15 74 a0 45 00 8b cb 8a 84 0d f4 fd ff ff 88 84 0d f0 fc ff ff 41 84 c0 75 ed 8d 85 f0 fc ff ff 6a 5c 50 e8 [2] 02 00 59 59 85 c0 74 02 88 18 53 68 80 00 00 00 6a 02 53 53 68 00 00 00 40 8d 85 f8 fe ff ff 50 ff 15 1c a0 45 00 8b f8 83 ff ff 0f 84 a7 00 00 00 b9 78 50 47 00 8d 51 01 8a 01 41 84 c0 75 f9 2b ca 8d 95 f4 fd ff ff 8d 72 01 8a 02 42 84 c0 75 f9 2b d6 8d b5 f8 fe ff ff 8d 5e 01 8a 06 46 84 c0 75 f9 2b f3 83 c1 14 8d 04 56 03 c1 e8 [2] 02 00 8b f4 8d 85 f8 fe ff ff 50 8d 85 f0 fc ff ff 50 8d 85 f4 fd ff ff 50 50 68 78 50 47 00 56 ff 15 a0 a1 45 00 8b ce 83 c4 18 8d 51 01 8a 01 41 84 c0 75 f9 33 db 8d 85 ec fc ff ff 53 50 2b ca 51 56 57 ff 15 88 a0 45 00 57 ff 15 7c a0 45 00 53 53 53 8d 85 f8 fe ff ff 50 68 [2] 45 00 53 ff 15 94 a1 45 00 8d a5 e0 fc ff ff 5f 5e 5b 8b }
        $s4 = { 51 a1 34 52 47 00 33 c5 89 45 fc 56 68 [2] 46 00 68 [2] 46 00 68 [2] 46 00 6a 11 e8 c6 fb ff ff 8b f0 83 c4 10 85 f6 74 12 ff 75 0c 8b ce ff 75 08 ff 15 a8 a1 45 00 ff d6 eb 14 6a 00 ff 75 0c ff 75 08 ff 15 4c a1 45 00 50 e8 d6 00 00 00 8b 4d fc 33 cd 5e e8 [2] fe ff 8b e5 }
        $s5 = { 8b ec 6a ff 68 [2] 45 00 64 a1 00 00 00 00 50 83 ec 44 a1 34 52 47 00 33 c5 89 45 f0 53 56 57 50 8d 45 f4 64 a3 00 00 00 00 8b f1 8b 3d 04 a0 45 00 68 00 00 00 f0 6a 01 6a 00 6a 00 56 c7 06 00 00 00 00 ff d7 85 c0 75 60 ff 15 54 a0 45 00 6a 08 6a 01 6a 00 68 [2] 45 00 56 8b d8 ff d7 85 c0 75 46 6a 28 6a 01 50 68 [2] 45 00 56 ff d7 85 c0 75 35 53 ff 15 58 a0 45 00 68 [2] 45 00 8d 4d d8 e8 ?? 8a fd ff 8d 45 d8 c7 45 fc 00 00 00 00 50 8d 4d b0 e8 d3 00 00 00 68 [2] 47 00 8d 45 b0 50 e8 [2] 00 00 8b c6 8b 4d f4 64 89 0d 00 00 00 00 59 5f 5e 5b 8b 4d f0 33 cd e8 [2] 00 00 }
    condition:
        uint16(0) == 0x5A4D and filesize > 100KB and 4 of ($s*)
}
