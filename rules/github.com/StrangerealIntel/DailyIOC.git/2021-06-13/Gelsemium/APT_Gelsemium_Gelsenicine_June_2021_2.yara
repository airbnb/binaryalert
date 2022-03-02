rule APT_Gelsemium_Gelsenicine_June_2021_2 {
   meta:
        description = "Detect Gelsenicine malware (Loader - Variant 2)"
        author = "Arkbird_SOLG"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2021/06/eset_gelsemium.pdf"
        date = "2021-06-12"
        hash1 = "6eaeca0cf28e74de6cfd82d29a3c3cc30c2bc153ac811692cc41ee290d766474"
        hash1 = "d986207bc108e55f4b110ae208656b415d2c5fcc8f99f98b4b3985e82b9d5e5b"
        hash1 = "ec491de0e2247f64b753c4ef0c7227ea3548c2f222b547528dae0cf138eca53a"
        tlp = "white"
        adversary = "Gelsemium"
   strings:      
            $s1 = { 48 53 48 83 ec 30 48 c7 44 24 20 fe ff ff ff 48 8b d9 c7 44 24 40 00 00 00 00 8b 05 [3] 00 a8 01 0f 85 96 00 00 00 83 c8 01 89 05 [3] 00 33 c0 88 44 24 40 4c 8d 44 24 40 48 8d 15 [3] 00 48 8d 0d [3] 00 ff 15 [2] 00 00 90 33 c0 88 44 24 48 4c 8d 44 24 48 48 8d 15 [3] 00 48 8d 0d [3] 00 ff 15 [2] 00 00 90 33 c0 88 44 24 40 4c 8d 44 24 40 48 8d 15 [3] 00 48 8d 0d [3] 00 ff 15 [2] 00 00 90 33 c0 88 44 24 48 4c 8d 44 24 48 48 8d 15 [3] 00 48 8d 0d [3] 00 ff 15 [2] 00 00 90 48 8d 0d [2] 00 00 e8 [2] 00 00 90 48 c7 43 08 00 00 00 00 48 c7 43 10 00 00 00 00 48 c7 43 18 00 00 00 00 4c 8d 0d [3] 00 4c 8d 05 [3] 00 33 d2 48 8b cb e8 86 f9 ff ff 48 8b c3 48 83 c4 30 }
            $s2 = { 54 00 65 00 6d 00 70 00 2f 00 00 00 00 00 00 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 2f 00 00 00 00 00 53 00 79 00 73 00 74 00 65 00 6d 00 2f 00 00 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2f }
            $s3 = { 48 8b ca e8 [3] 00 48 39 5e 08 75 05 48 8b c3 eb 08 48 8b 46 10 48 2b 46 08 3b c3 0f 4c c3 48 63 c8 e8 [3] 00 48 89 47 08 48 8b 56 10 48 8b 4e 08 4c 8b d8 eb 10 4c 3b db 74 05 8a 01 41 88 03 49 ff c3 48 ff c1 48 3b ca 75 eb 4c 89 5f 10 4c 89 5f 18 48 8b c7 48 83 c4 20 5f 5e }
            $s4 = { 45 33 c9 45 33 c0 ba 80 00 00 00 48 8b ce e8 16 f2 ff ff 84 c0 74 71 48 8d 53 18 41 b8 20 00 00 00 48 8b ce e8 e4 f4 ff ff 84 c0 74 5b 48 8d 53 38 41 b8 20 00 00 00 48 8b ce e8 56 f9 ff ff 84 c0 74 45 48 8b 43 10 48 8b 0d [3] 00 48 3b c1 74 0d 48 8b d8 48 8b 00 48 3b c1 75 f5 eb 1b 48 8b 43 08 eb 07 48 8b d8 48 8b 40 08 48 3b 58 10 74 f3 48 39 43 10 48 0f }
    condition:
            uint16(0) == 0x5a4d and filesize > 30KB and 3 of ($s*) 
}
