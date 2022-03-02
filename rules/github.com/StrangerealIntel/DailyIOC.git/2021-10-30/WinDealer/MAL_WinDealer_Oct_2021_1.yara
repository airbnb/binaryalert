rule MAL_WinDealer_Oct_2021_1 {
    meta:
        description = "Detect WinDealer implant"
        author = "Arkbird_SOLG"
        reference = "https://blogs.jpcert.or.jp/en/2021/10/windealer.html"
        date = "2021-10-30"
        hash1 = "1e9fc7f32bd5522dd0222932eb9f1d8bd0a2e132c7b46cfcc622ad97831e6128"
        hash2 = "b9f526eea625eec1ddab25a0fc9bd847f37c9189750499c446471b7a52204d5a"
        tlp = "white"
        adversary = "LuoYu"
    strings:
        $s1 = { 8b ec 81 ec 64 03 00 00 53 56 33 db 6a 64 8d 45 9c 53 50 e8 [2] 00 00 be 00 01 00 00 8d 85 9c fc ff ff 56 53 50 e8 [2] 00 00 56 8d 85 9c fd ff ff 53 50 e8 [2] 00 00 56 8d 85 9c fe ff ff 53 50 e8 [2] 00 00 83 c4 30 8d 45 9c 6a 64 50 ff 15 [2] 41 00 8d 85 9c fe ff ff 50 8d 85 9c fd ff ff 50 8d 85 9c fc ff ff 50 ff 75 9c e8 [2] ff ff 83 c4 10 38 9d 9c fe ff ff 5e 5b 75 20 8d 85 9c fe ff ff 50 8d 85 9c fd ff ff 50 8d 85 9c fc ff ff 50 ff 75 9c e8 [2] ff ff 83 c4 10 8d 85 9c fe ff ff 50 8d 85 9c fd ff ff 50 8d 85 9c fc ff ff 50 68 [2] 41 00 ff 75 08 ff 15 [2] 41 00 83 c4 14 6a }
        $s2 = { 8b ec b8 40 1c 00 00 e8 [2] 00 00 56 57 33 ff 68 [2] 41 00 89 7d f8 ff 15 [2] 41 00 8b f0 6a 32 8d 45 c0 57 50 e8 [2] 00 00 83 c4 10 3b f7 74 1c 6a 5c 56 ff 15 [2] 41 00 59 3b c7 59 74 0d 40 50 8d 45 c0 50 e8 [2] 00 00 59 59 be 00 04 00 00 8d 85 c0 f7 ff ff 56 57 50 89 75 fc e8 [2] 00 00 8d 45 fc 50 8d 85 c0 f7 ff ff 50 e8 fb fd ff ff 83 c4 14 39 7d fc 75 24 56 8d 85 c0 f7 ff ff 57 50 89 75 fc e8 [2] 00 00 8d 45 fc 50 8d 85 c0 f7 ff ff 50 e8 ?? fc ff ff 83 c4 14 56 8d 85 c0 fb ff ff 57 50 e8 [2] 00 00 8d 85 c0 fb ff ff 50 e8 [2] 00 00 8d 85 c0 fb ff ff 50 e8 [2] 00 00 83 c4 14 83 7d fc 0a 7e 3e 83 f8 0a 7e 6d 8d 45 c0 50 8d 85 c0 fb ff ff 50 8d 85 c0 f7 ff ff 50 8d 85 c0 e3 ff ff 68 [2] 41 00 50 ff 15 [2] 41 00 50 8d 85 c0 e3 ff ff 50 e8 4d fd ff ff 83 c4 1c 89 45 f8 eb 5c 83 f8 0a 7e 2f 8d 45 c0 50 8d 85 c0 fb ff ff 50 8d 85 c0 e3 ff ff 68 [2] 41 00 50 ff 15 [2] 41 00 50 8d 85 c0 e3 ff ff 50 e8 16 fd ff ff 83 c4 18 eb c7 6a 43 8d 45 f4 68 [2] 41 00 50 ff 15 [2] 41 00 83 c4 0c 8d 45 f8 57 57 57 57 50 57 8d 45 f4 57 50 ff 15 [2] 41 00 8b 45 f8 }
        $s3 = { 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4e 65 74 77 6f 72 6b 5c 7b 34 44 33 36 45 39 37 32 2d 45 33 32 35 2d 31 31 43 45 2d 42 46 43 31 2d 30 38 30 30 32 42 45 31 30 33 31 38 7d 5c 25 73 5c 43 6f 6e 6e 65 63 74 69 6f 6e }
        $s4 = { 6d 61 63 3a 20 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 }
        $s5 = { 8b d8 59 85 db 59 74 57 56 e8 [2] 00 00 03 d8 53 ff 15 [2] 41 00 6a 00 50 e8 [2] ff ff 6a 64 8d 45 9c 6a 00 50 e8 [2] 00 00 83 c4 1c 8d 45 9c 68 [2] 41 00 68 [2] 41 00 50 ff 15 [2] 41 00 66 8b 8f d2 07 00 00 51 8a 8f d0 07 00 00 51 50 8d 45 9c 50 e8 ?? f1 ff ff 83 c4 1c 5f 5e 33 c0 5b c9 c3 55 }
    condition:
        uint16(0) == 0x5A4D and filesize > 80KB and 4 of ($s*) 
}
