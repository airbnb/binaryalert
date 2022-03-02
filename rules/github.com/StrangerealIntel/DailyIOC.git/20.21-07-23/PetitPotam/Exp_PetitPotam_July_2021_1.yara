rule Exp_PetitPotam_July_2021_1
{
    meta:
        description = "Detect PetitPotam exploit (local exploit version)"
        author = "Arkbird_SOLG"
        date = "2021-07-23"
        reference = "https://github.com/topotam/PetitPotam"
        hash1 = "10cbadc2c82178d3b7bdf96ab39b9e8580ee92c2038728b74d314e506c7a9144"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = "\\pipe\\lsarpc" fullword wide
        $s2 = { 5c 00 5c 00 25 00 73 00 5c 00 [4-12] 5c 00 [4-12] 00 2e 00 65 00 78 00 65 }
        $s3 = { 5c 00 5c 00 25 00 73 00 00 00 00 00 6e 00 63 00 61 00 63 00 6e 00 5f 00 6e 00 70 }
        $s4 = { 23 46 69 6c 65 20 45 72 72 6f 72 23 28 25 64 29 20 3a }
        $s5 = { 43 6c 69 65 6e 74 20 68 6f 6f 6b 20 61 6c 6c 6f 63 61 74 69 6f 6e 20 66 61 69 6c 75 72 65 20 61 74 20 66 69 6c 65 20 25 68 73 20 6c 69 6e 65 20 25 64 }
        $s6 = { 50 e8 06 95 ff ff 83 c4 10 c7 85 00 ff ff ff 00 00 00 00 8b 85 00 ff ff ff 50 8d 8d 0c ff ff ff 51 8d 55 dc 52 8b 45 f4 50 e8 4e 7a ff ff 83 c4 10 89 45 e8 83 7d }
        $s7 = "Attack success!!!\n" fullword wide
        $s8 = { 8b 43 0c 56 83 e8 24 8d 73 20 50 56 8d 45 b4 50 8d 45 e8 50 e8 02 02 00 00 68 b8 52 4f 00 8d 45 b4 50 68 bc 52 4f 00 8d 45 e8 50 8b 43 0c 68 c0 52 4f 00 ff 75 10 83 e8 24 68 cc 52 4f 00 50 68 00 53 4f 00 56 68 0c 53 4f 00 68 20 53 4f 00 68 78 53 4f 00 8d 85 c0 fe ff ff 68 f4 00 00 00 50 e8 4e 91 ff ff 83 c4 4c 8d 85 c0 fe ff ff 50 6a 04 }
        $s9 = { 25 73 25 73 25 70 25 73 25 7a 64 25 73 25 64 25 73 25 73 25 73 25 73 25 73 }
        $s10 = { 25 00 6c 00 73 00 28 00 25 00 64 00 29 00 20 00 3a 00 20 00 25 00 6c 00 73 }
    condition:
       uint16(0) == 0x5A4D  and filesize > 50KB and 7 of ($s*) 
}  
