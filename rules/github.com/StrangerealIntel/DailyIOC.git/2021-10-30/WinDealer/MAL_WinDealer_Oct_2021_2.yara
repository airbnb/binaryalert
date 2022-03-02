rule MAL_WinDealer_Oct_2021_2 {
    meta:
        description = "Detect modules from WinDealer implant"
        author = "Arkbird_SOLG"
        reference = "https://blogs.jpcert.or.jp/en/2021/10/windealer.html"
        date = "2021-10-30"
        hash1 = "0c365d9730a10f1a3680d24214682f79f88aa2a2a602d3d80ef4c1712210ab07"
        hash2 = "2eef273af0c768b514db6159d7772054d27a6fa8bc3d862df74de75741dbfb9c"
        tlp = "white"
        adversary = "LuoYu"
    strings:
        $s1 = { 81 ec f0 03 00 00 53 55 8b d9 56 8d 44 24 0c 57 8d 4c 24 18 50 51 c7 44 24 18 f4 01 00 00 ff 15 0c [2] 10 85 c0 0f 85 ?? 01 00 00 68 [3] 10  }
        $s2 = { 81 ec 24 03 00 00 53 56 8d 44 24 18 57 50 68 03 01 00 00 6a 00 68 [2] 03 10 68 01 00 00 80 c7 44 24 20 00 00 00 00 ff 15 10 [2] 10 85 c0 0f 85 ?? 01 00 00 8d 4c 24 0c 8d 54 24 20 51 52 8b 1d 00 [2] 10 50 68 3f 01 0f 00 50 50 50 8b 44 24 38 68 [2] 03 10 50 ff d3 85 c0 0f 85 ?? 01 00 00 8d 4c 24 0c 8d 54 24 10 51 52 50 68 3f 01 0f 00 50 50 50 8b 44 24 3c 68 [2] 03 10 50 ff d3 85 c0 0f 85 ?? 01 00 00 bf [2] 03 10 83 c9 ff f2 ae f7 d1 2b f9 8d ?? 24 }
        $s3 = "%s\\%s\\V5_History.dat" wide
        $s4 = { 8b 8c 24 2c 02 00 00 8b 94 24 28 02 00 00 55 57 51 52 8d 44 24 24 53 50 89 74 24 2c e8 05 fb ff ff b9 41 00 00 00 33 c0 8d bc 24 34 01 00 00 83 c4 18 f3 ab 8d 8c 24 1c 01 00 00 51 68 04 01 00 00 ff 15 [2] 03 10 b9 41 00 00 00 33 c0 8d 7c 24 18 50 f3 ab [3] 01 }
        $s5 = { 56 6a 10 e8 [3] 00 8b f0 85 f6 74 3a 8b 4c 24 0c 8d 46 04 85 c9 c7 06 [3] 10 c7 00 00 00 00 00 50 74 11 8b 44 24 0c 50 e8 [3] 00 89 46 08 8b c6 5e c3 8b 4c 24 0c 51 e8 [3] 00 89 46 08 8b c6 5e c3 33 }
    condition:
        uint16(0) == 0x5A4D and filesize > 80KB and 4 of ($s*) 
}
