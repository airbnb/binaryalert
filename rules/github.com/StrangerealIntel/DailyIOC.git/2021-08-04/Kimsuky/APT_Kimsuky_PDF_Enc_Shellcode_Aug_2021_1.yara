rule APT_Kimsuky_PDF_Enc_Shellcode_Aug_2021_1
{
    meta:
        description = "Detect encoded Kimsuky shellcode used in fake PDF against South Korea"
        author = "Arkbird_SOLG"
        date = "2021-08-03"
        reference = "Internal Research"
        hash1 = "83292ba7a1ddda6acf32181c693aa85b9e433fcb908a94ebccbed0f407a1a021"
        hash2 = "512ad244c58064dfe102f27c9ec8814f3e3720593fe1e3ed48a8cb385d52ff84"
        level = "Experimental"
        tlp = "white"
        adversary = "Kimsuky"
    strings:
        $x1 = { 52 2f 53 2f 4a 61 76 61 53 63 72 69 70 74 3e 3e 0d 65 6e 64 6f 62 6a 0d }
        $s1=  { 78 9c ec bd 6b 97 eb 4a 72 25 f6 57 8e b5 96 67 75 4f 6b 24 f0 25 8f a6 d5 b3 16 59 00 6a c8 19 80 06 86 28 9b 65 d9 b3 7a 58 b7 59 97 3c ea 96 fb 21 92 90 fb bf 3b 76 64 c6 23 93 f5 38 47 6a 8f f5 41 1f ee ba c5 03 12 40 66 46 46 c6 63 c7 8e 7f f8 }
        $s2 = { 94 fe 9b f1 c7 1f e8 e3 0f f4 f1 87 19 fd 37 ff f9 17 fc db 8f f4 ed e2 e7 5f fe 1b fe ff df 7e fc 8b df fe f0 f7 5f 7f 79 f8 e1 27 7f f9 7f fc 5f cb 7f f7 fc cb 7f 37 16 ff ee af ff f6 67 7f fb 97 7f fb b7 bf f8 3f ff f2 f8 e7 74 e3 9f fe fc cb e5 f5 c7 af 3f 7c f9 c9 8f 5f fe 06 3f f9 fa c3 af 8f bf 7f a5 87 d3 fd e9 26 bf 7f fd f1 }
        $s3 = { b6 7c 2a db e2 39 ae 67 75 d9 ee 56 ab 7e 27 f2 b5 2e ba 61 3d a5 f5 88 f3 5b 3f f6 b4 b6 6d d1 c9 fb ae 9a 20 93 63 5c cf 69 73 6e a6 dd 4e d6 6b 98 f4 67 92 01 fa 9e 3d 6f 98 f7 95 3c ef eb aa 3f 37 85 bd ef 70 69 c6 ba ea 77 4f }
        $s4 = { 4d 51 d7 5b 7d de f2 96 c8 0b dd bf d9 2d e9 7d 87 85 ec 87 b6 a4 cf 43 dc 1f 55 37 d2 fd 2b 95 df 20 6f 45 ab e3 e1 eb 24 df 71 ff 40 fe 69 3f }
        $s5 = { 0f 35 fc 43 53 cf 03 67 d3 85 fb 51 b6 49 5f 40 fa 5d a2 3f 7d 31 fb 0b 3d 6f 53 69 ff 78 aa 37 e8 f3 12 fe 35 3e 43 90 7c 9c e3 73 a6 78 1c 9c 21 ec bf 20 df eb f0 5a b7 76 6f fb ad 96 53 57 0f a4 fc c3 6a f5 6d fe 41 fc 19 ed f7 4f 78 3a e9 1f f8 23 3d 2b 8d 2f 86 79 d6 7b b2 f8 e0 85 f2 51 25 fc 70 8c }
    condition:
       uint32(0) == 0x46445025 and filesize > 25KB and $x1 and 4 of ($s*) 
}  

