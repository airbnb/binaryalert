rule RAN_ALPHV_Dec_2021_1
{
    meta:
        description = "Detect AlphV ransomware (Nov and Dec 2021)"
        author = "Arkbird_SOLG"
        date = "2021-12-09"
        reference = "Internal Research"
        hash1 = "3d7cf20ca6476e14e0a026f9bdd8ff1f26995cdc5854c3adb41a6135ef11ba83"
        hash2 = "7e363b5f1ba373782261713fa99e8bbc35ddda97e48799c4eb28f17989da8d8e"
	hash3 = "cefea76dfdbb48cfe1a3db2c8df34e898e29bec9b2c13e79ef40655c637833ae"
	hash4 = "731adcf2d7fb61a8335e23dbee2436249e5d5753977ec465754c6b699e9bf161"
        tlp = "white"
        adversary = "BlackCat"
    strings:
        $s1 = { ff b4 24 [2] 00 00 6a 00 ff 35 ?? e1 ?? 00 e8 [3] 00 8d 8c 24 [2] 00 00 ba [3] 00 68 c0 1f 00 00 e8 [3] ff 83 c4 04 ?? bc 24 [2] 00 00 }
        $s2 = { 85 f6 74 47 8b 3d ?? e1 ?? 00 85 ff 0f 85 81 00 00 00 eb 60 68 [3] 00 6a 00 6a 00 e8 [2] 04 00 85 c0 0f 84 99 01 00 00 89 c1 31 c0 f0 0f b1 0d ?? e1 ?? 00 0f 84 f0 fe ff ff 89 c6 51 e8 [2] 04 00 89 f1 e9 e1 fe ff ff 68 [3] 00 ff 35 ?? e1 ?? 00 e8 [2] 04 00 85 c0 0f 84 32 03 00 00 89 c6 a3 ?? e1 ?? 00 8b 3d ?? e1 ?? 00 85 ff 75 1f 68 [3] 00 ff 35 ?? e1 ?? 00 e8 [2] 04 00 85 c0 0f 84 09 03 00 00 89 c7 a3 ?? e1 ?? 00 89 74 24 18 e8 [2] 04 00 8b 35 ?? e1 ?? 00 89 44 24 14 85 f6 75 1f 68 [3] 00 ff 35 ?? e1 ?? 00 e8 [2] 04 00 85 c0 0f 84 b8 01 00 00 89 c6 a3 ?? e1 ?? 00 8d 44 24 70 c7 44 24 64 00 00 00 00 c7 44 24 60 00 00 00 00 68 0c 01 00 00 6a 00 50 e8 [2] 04 00 83 }
        $s3 = { 8b 38 89 4d ec 89 55 ?? 74 34 a1 ?? e1 ?? 00 85 c0 75 0e e8 [3] 00 85 c0 74 14 a3 ?? e1 ?? 00 53 6a 00 50 e8 [3] 00 89 c6 85 c0 75 13 89 d9 ba 01 00 00 00 e8 [3] ff 0f 0b be 01 00 00 00 53 57 56 e8 [3] 00 83 c4 0c 8d 04 1e 8d 4d }
        $s4 = { 83 c4 0c c7 45 ?? 00 00 00 00 c7 45 ?? 02 00 00 89 89 75 ?? 8d 45 ?? c7 45 ?? 00 00 00 00 c7 45 ?? 00 00 00 00 6a 10 50 57 e8 [3] 00 83 f8 ff 0f 84 ?? 02 00 00 f6 45 9c ff }
    condition:
       uint16(0) == 0x5A4D and filesize > 300KB and all of ($s*) 
}  
