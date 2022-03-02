rule APT_APT_C_23_Micropsia_Mar_2021_2 {
   meta:
        description = "Detect Micropsia used by APT-C-23 (Build 2020)"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-03-31"
        hash1 = "d9b938d89a13620aabe81e0a9d02778cad8658cbfd6f15e7dab47b1118b53237"
        hash2 = "42f40fb2e4f971807fcb771c9aacc5a2361fdcdaf3eaafc31b22096d81dd0666"
        level = "experimental"
   strings:
        // code reuse
        $code1 = { 8d 45 f8 8b 15 90 c7 69 00 e8 1e 05 d5 ff c7 45 d0 00 00 00 00 c7 45 d4 00 00 00 00 8b 45 d8 8b 58 5c 85 db 74 22 8b c3 8b 10 ff 12 52 50 8b 45 d8 8b 40 5c e8 af 4b db ff 29 04 24 19 54 24 04 58 5a 89 45 d0 89 55 d4 6a 04 8d 45 d8 50 6a 2d 8b 45 d8 8b 80 a4 00 00 00 50 e8 59 cd ff ff c7 45 c4 02 00 00 00 6a 04 8d 45 c4 50 6a 3f 8b 45 d8 8b 80 a4 00 00 00 50 e8 3b cd ff ff c7 45 c4 01 00 00 00 6a 04 8d 45 c4 50 6a 3f 8b 45 d8 8b 80 a4 00 00 00 50 e8 1d cd ff ff 33 c0 5a 59 59 64 89 10 68 aa df 6b 00 8b 45 e8 e8 a0 }
        $code2 = { 6a 00 8b 45 d0 50 6a 00 6a 00 6a 00 6a 00 8b 45 d8 8b 80 a4 00 00 00 50 e8 d1 cc ff ff 85 c0 75 19 8b 15 50 a7 6e 00 8b 4d e8 8b 45 ec e8 9c fc }
        $code3 = { 8d 4d f4 8b 45 d4 8b 40 0c ba 01 00 00 00 8b 18 ff 53 0c 8b 45 d4 8b 50 10 a1 bc 1c 6f 00 e8 82 bc ff ff 8b 55 f4 a1 bc 1c 6f 00 e8 75 bc ff ff 8b 45 f4 ba f4 7c 6d 00 e8 a0 4c d3 ff 0f 85 cf 00 00 00 ba 08 7d 6d 00 a1 bc 1c 6f 00 e8 53 bc ff ff 33 c0 55 68 9a 76 6d 00 64 ff 30 64 89 20 33 c0 89 45 dc 8d 55 9c b8 38 7c 6d 00 e8 7b 86 d5 ff ff 75 9c 68 50 7c 6d 00 8d 55 98 b8 09 00 00 00 e8 c6 c4 ff ff ff 75 98 68 60 7c 6d 00 8d 45 dc ba 04 00 00 00 e8 91 4b d3 ff e8 c4 22 d5 ff dd 5d c0 9b ff 75 c4 ff 75 c0 8d 4d e0 8b 15 30 ab 6e 00 b8 70 7c 6d 00 e8 97 32 d5 ff 8b 45 d4 83 c0 14 }
        $s1 = { 4a 00 50 00 45 00 47 00 20 00 49 00 6d 00 61 00 67 00 65 00 20 00 46 00 69 00 6c 00 65 00 25 00 53 00 63 00 68 00 65 00 6d 00 65 00 20 00 22 00 25 00 73 00 22 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 66 00 6f 00 72 00 20 00 25 00 73 } // JPEG Image File%Scheme "%s" already registered for %s
        $s2 = "Download start ." fullword wide
        $s3 = "application/x-msdownload" fullword wide
        $s4 = "Start Download File" fullword wide
        $s5 = "getHttpDownload" fullword ascii
        $s6 = "Download start ." fullword wide
        $s7 = "-start" fullword wide
        $s8 = "-Winapi.ImageHlp" fullword ascii
        $s9 = "postHttpDownload" fullword ascii
   condition:
        uint16(0) == 0x5a4d and filesize > 50KB and 2 of ($code*) and 5 of ($s*)
}
