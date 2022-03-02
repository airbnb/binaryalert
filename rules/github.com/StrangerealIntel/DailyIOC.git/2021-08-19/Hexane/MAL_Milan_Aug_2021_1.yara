rule MAL_Milan_Aug_2021_1
{
   meta:
      description = "Detect Milian backdoor used by Hexane group (aka Siamesekitten)"
      author = "Arkbird_SOLG"
      reference = "https://www.clearskysec.com/siamesekitten/"
      date = "2021-08-18"
      hash1 = "b46949feeda8726c0fb86d3cd32d3f3f53f6d2e6e3fcd6f893a76b8b2632b249"
      hash2 = "4f1b8c9209fa2684aa3777353222ad1c7716910dbb615d96ffc7882eb81dd248"
      tlp = "White"
      adversary = "Hexane"
   strings:
         $c1 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 70 00 69 00 6e 00 67 00 20 00 [2-6] 2e 00 [2-6] 2e 00 [2-6] 2e 00 [2-6] 20 00 2d 00 6e 00 20 00 31 00 20 00 2d 00 77 00 20 00 [2-8] 20 00 3e 00 20 00 4e 00 75 00 6c 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 71 00 20 00 22 00 25 00 73 00 22 00 20 00 26 00 20 00 77 00 61 00 69 00 74 00 66 00 6f 00 72 00 20 00 61 00 20 00 34 00 20 00 26 00 20 00 63 00 6f 00 70 00 79 00 20 00 22 00 25 00 73 00 22 00 20 00 22 00 25 00 73 00 22 00 20 00 20 00 26 00 20 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 52 00 75 00 6e 00 20 00 2f 00 54 00 4e 00 20 00 22 }
         $c2 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 70 00 69 00 6e 00 67 00 20 00 [2-6] 2e 00 [2-6] 2e 00 [2-6] 2e 00 [2-6] 20 00 2d 00 6e 00 20 00 31 00 20 00 2d 00 77 00 20 00 [2-8] 20 00 3e 00 20 00 4e 00 75 00 6c 00 20 00 26 00 20 00 72 00 6d 00 64 00 69 00 72 00 20 00 2f 00 73 00 20 00 2f 00 71 00 20 00 22 00 25 00 73 00 22 00 20 00 26 00 20 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 2f 00 74 00 6e }
         $s1 = { 2d 2d 2d 2d 2d 2d [1-8] 0d 0a 43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 6e 61 6d 65 3d 22 25 73 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 25 73 22 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f }
         $s2 = { 5b 00 25 00 64 00 3a 00 25 00 64 00 3a 00 25 00 64 00 3a 00 25 00 64 00 28 00 25 00 64 00 29 00 5d }
         $s3 = { 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 79 00 70 00 65 00 3a 00 20 00 6d 00 75 00 6c 00 74 00 69 00 70 00 61 00 72 00 74 00 2f 00 66 00 6f 00 72 00 6d 00 2d 00 64 00 61 00 74 00 61 00 3b 00 20 00 62 00 6f 00 75 00 6e 00 64 00 61 00 72 00 79 00 3d 00 2d 00 2d 00 2d 00 2d}
         $s4 = { 8d 8d 7c ee ff ff 51 6a 00 6a 00 50 ff 15 ?? b2 4b 00 85 c0 0f 84 a9 0f 00 00 8d 85 e0 fb ff ff 50 e8 ?? e0 ff ff 59 50 8d 85 e0 fb ff ff 50 8d 4b 20 e8 [2] 00 00 6a 00 ff b5 94 ee ff ff 8d 85 e0 fb ff ff 50 ff 33 ff 15 ?? b2 4b 00 8b d0 89 95 e8 ee ff ff 85 d2 0f 84 65 0f 00 00 6a 02 5e 33 c9 b8 00 00 80 00 39 b5 88 ee ff ff 0f 44 c8 83 bd 94 ef ff ff 08 51 8d 85 80 ef ff ff 0f 43 85 80 ef ff ff 33 c9 51 51 51 ff b5 a8 ee ff ff 50 52 ff 15 ?? b2 4b 00 8b f0 89 b5 48 ef ff ff 85 f6 0f 84 fb 0e 00 00 80 7b 04 00 8b 3d ?? b2 4b 00 75 23 6a 02 58 39 85 88 ee ff ff 75 18 6a 04 8d 85 20 ef ff ff c7 85 20 ef ff ff 00 31 00 00 50 6a 1f 56 ff d7 c6 85 47 ef ff ff 00 33 c9 c7 85 f0 ee ff ff 18 00 00 00 8b c1 41 89 8d 20 ef ff ff 83 f8 03 0f 83 88 0e 00 00 83 bb d8 00 00 00 00 76 31 8d 83 c8 00 00 00 83 78 14 08 72 02 8b 00 68 00 00 00 01 ff b3 d8 00 00 00 50 56 ff 15 b8 b2 4b 00 85 c0 75 0c ff 15 40 b0 4b 00 89 83 f8 00 00 00 8d b3 a8 00 00 00 83 7e 10 00 76 7a 68 ?? b9 4c 00 8d 8d 98 ef ff ff e8 [2] 00 00 6a ff 33 c0 8d 8d 98 ef ff ff 6a 00 40 56 88 45 fc e8 [2] 00 00 83 bd ac ef ff ff 08 8d 85 98 ef ff ff 8b b5 48 ef ff ff 0f 43 85 98 ef ff ff 68 00 00 00 01 ff b5 a8 ef ff ff 50 56 ff 15 b8 b2 4b 00 85 c0 75 0c ff 15 40 b0 4b 00 89 83 f8 }
         $s5 = { 6a 00 ff b5 40 ef ff ff ff b3 88 01 00 00 ff 15 30 b0 4b 00 50 57 6a ff 56 8b b5 48 ef ff ff 56 ff 15 ?? b2 4b 00 85 c0 0f 85 b2 02 00 00 8d bd 00 ef ff ff ab ab ab ab 8d 85 00 ef ff ff 50 ff 15 ?? b2 4b 00 85 c0 0f 84 74 02 00 00 8b 95 04 ef ff ff 85 d2 0f 84 4f 01 00 00 33 c0 8d bd b8 ee ff ff 6a 06 59 f3 ab 83 a5 c8 ee ff ff 00 8d bd f4 ee ff ff 83 a5 c4 ee ff ff 00 40 89 85 bc ee ff ff 89 85 cc ee ff ff 33 c0 ab c7 85 b8 ee ff ff 03 00 00 00 89 95 c0 ee ff ff ab ab 8d 43 08 83 }
   condition:
      uint16(0) == 0x5A4D and filesize > 15KB and 1 of ($c*) and 4 of ($s*)
}
