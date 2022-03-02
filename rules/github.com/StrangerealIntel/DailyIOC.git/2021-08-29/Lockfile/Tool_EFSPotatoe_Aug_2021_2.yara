rule Tool_EFSPotatoe_Aug_2021_2 {
   meta:
        description = "Detect EFSPotatoe tool (Generic rule)"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-08-27"
        hash1 = "c372c54b11465688201e2d48ffd5fd5b0ca49360858a70ce8413f5c9e24c8050"
        hash2 = "441cb0576151b2e5b5127be72a5bcdf3577a596f0a4e1f2c6836248fe07eb818"
        hash3 = "47b85abee8a07e79ad95f48a3e3addf7235144b67b0350e2f9ac80e66f97e583"
        hash4 = "7bcb25854ea2e5f0b8cfca7066a13bc8af8e7bac6693dea1cdad5ef193b052fd"
        adversary = "-"
   strings:
        $s1 = { 5c 00 70 00 69 00 70 00 65 00 5c 00 6c 00 73 00 61 00 72 00 70 00 63 }
        $s2 = "ncacn_np" fullword wide
        $s3 = { 5c 00 5c 00 25 00 73 00 5c 00 [1-20] 00 5c 00 [1-20] 00 }
        $s4 = { 63 00 36 00 38 00 31 00 64 00 34 00 38 00 38 00 2d 00 64 00 38 00 35 00 30 00 2d 00 31 00 31 00 64 00 30 00 2d 00 38 00 63 00 35 00 32 00 2d 00 30 00 30 00 63 00 30 00 34 00 66 00 64 00 39 00 30 00 66 00 37 00 65 }
        $s5 = { 00 72 48 02 00 70 28 0e 00 00 0a 73 15 00 00 0a 6f 16 00 00 0a 28 0a 00 00 0a 28 06 00 00 0a 00 38 4a 02 00 00 }
   condition:
        uint16(0) == 0x5a4d and filesize > 10KB and 4 of ($s*)
}
