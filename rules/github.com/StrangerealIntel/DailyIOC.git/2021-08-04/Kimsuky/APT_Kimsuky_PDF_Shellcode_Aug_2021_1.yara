rule APT_Kimsuky_PDF_Shellcode_Aug_2021_1
{
    meta:
        description = "Detect Kimsuky shellcode used in fake PDF against South Korea"
        author = "Arkbird_SOLG"
        date = "2021-08-03"
        reference = "Internal Research"
        hash1 = "7900ca98a6fbed74aa5a393758c43ad7abc9d8c73c3fbab7af93bae681065f4e"
        hash2 = "359ab5e0b57da0307ca9472e5b225dcd0f9dc9bf2efd2f15b1ca45b78791b6bc"
        hash3 = "5ea7a724d99fab3f05f50dccd57db59451334ac8640c532d426df319dad55c9e"
        level = "Experimental"
        tlp = "white"
        adversary = "Kimsuky"
    strings:
        $x1 = { 52 2f 53 2f 4a 61 76 61 53 63 72 69 70 74 3e 3e 0d 65 6e 64 6f 62 6a 0d }
        $s1=  { 48 89 d4 57 e9 6f 22 47 16 ff ec 91 e6 7f a8 20 65 0c 43 db 53 7d e1 b6 }
        $s2 = { 48 5e 64 35 50 98 b6 9b 63 9b 86 c1 1b f9 7f df f7 ea ea aa a6 31 78 f2 65 77 8e a6 bb }
        $s3 = { ef a7 2c 5e 96 b8 84 06 66 b8 9e 54 cb 51 80 f1 66 35 65 69 0a 38 c5 35 7e 62 48 a2 18 c4 2b 76 0f ba 00 07 6a 2e c5 e3 71 66 ac 6d 12 f6 95 99 0b 37 a3 6c d1 5f 64 b3 fb 0e a0 8d f5 d9 f3 24 61 e9 18 c9 d9 6a a5 94 48 d3 5f e2 19 93 5a fe 33 99 e7 91 50 f5 8e 6e 5b 1d 07 1e 21 3c 2e 3c 7c bb 55 9f ad 2e 3c 7c 1f 1f }
        $s4 = { b1 9a 3c f7 ce 9e 51 79 f2 c4 d9 13 3a a9 ee f0 95 3d fa be 86 ad cd ea d1 90 d4 4e 18 3a 51 58 b4 e9 97 b7 48 e5 62 32 36 5b 6c d8 ae a4 d2 1d b6 92 a7 af 67 15 c5 52 96 44 02 51 58 1c c7 1c a5 2f c3 28 d0 cf 56 10 f1 27 fd 1f 7e b7 9e 30 b5 9c e0 60 02 37 9e 44 4c 62 30 cb 36 2a a6 c4 f3 7c f1 5b 9e 25 73 d5 d4 f4 f0 fd 8a 1d 89 e1 9d 31 4b 59 ce 0c 33 b6 ab 4d 3b 5f a7 69 21 a0 42 11 13 f3 70 9f 27 33 b6 58 e7 38 49 2d 97 18 de bf c3 c2 97 35 4c 65 70 61 6a d7 1c 3e 7e f2 04 7e d1 39 bc a3 ad 5b 1e 51 65 0d 70 a5 4a 55 b3 89 d9 71 c7 1b 77 4f 15 41 0e 0a 09 28 ab 0d 14 43 af 55 f4 6c }
        $s5 = { 91 42 d1 ed c0 be 73 73 3e 35 8f b4 8e 38 f9 97 ba f9 58 d6 8b 37 a8 82 29 e7 4d 35 ea e2 ba 48 e0 61 b5 a4 f6 d4 4b 90 6a 98 89 fb 81 39 8b 3b 18 de dc 9d b7 36 ec d2 f1 51 56 1a 10 d3 b5 6b b4 95 f9 1e 86 97 9c 71 d5 4b 9a fb 0c 89 ec 3c d4 1d ac 51 34 9f 63 4d 51 59 3c b1 11 7a cd 79 a0 7a d6 43 48 52 d6 9a 4f bb 70 9a f6 3d a5 8d 72 37 9c 5b 66 e8 37 b5 48 25 80 74 e3 c7 46 ae 45 47 8e b4 e5 e8 3a 52 cd d3 87 c1 67 27 d7 62 54 6e 52 86 71 c5 c1 9f 2c ee 31 fa 2e c9 6a 7b a0 60 50 9f 16 17 f9 45 cd d9 b5 00 78 e4 6c 6b b5 f2 8e e1 bd 00 7d 74 c5 a5 45 35 0c dc 79 9c 3d 82 6a 86 92 }
    condition:
       uint32(0) == 0x46445025 and filesize > 25KB and $x1 and 4 of ($s*) 
}  
