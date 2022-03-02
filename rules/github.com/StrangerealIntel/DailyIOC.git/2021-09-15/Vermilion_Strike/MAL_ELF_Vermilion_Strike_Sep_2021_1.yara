rule MAL_ELF_Vermilion_Strike_Sep_2021_1 {
   meta:
        description = "Detect the ELF version of Vermilion Strike implant"
        author = "Arkbird_SOLG"
        reference1 = "https://www.intezer.com/blog/malware-analysis/vermilionstrike-reimplementation-cobaltstrike/"
        date = "2021-09-14"
        hash1 = "294b8db1f2702b60fb2e42fdc50c2cee6a5046112da9a5703a548a4fa50477bc"
        level = "experimental"
        tlp = "White"
        adversary = "Vermilion Strike"
    strings:
        $s1 = { be bd f8 40 00 41 55 49 89 fd bf a3 f8 40 00 41 54 55 53 48 81 ec 20 04 00 00 e8 4f cb ff ff 48 85 c0 48 89 c5 0f 84 af 01 00 00 48 8d 5c 24 20 41 bc 0a 00 00 00 41 be b0 32 40 00 66 90 48 89 ea be c8 00 00 00 48 89 df e8 30 cd ff ff 48 85 c0 0f 84 4f 01 00 00 80 7c 24 20 23 74 e0 bf b4 f8 40 00 48 89 de 4c 89 e1 f3 a6 75 d1 be d4 1d 41 }
        $s2 = { 8b 43 14 8b 73 10 8b 4b 0c 8d 56 01 44 8d 80 6c 07 00 00 be 70 21 41 00 31 c0 e8 ed 34 ff ff 48 85 ed 74 28 8b 4b 04 8b 53 08 48 89 ef 44 8b 03 48 83 c4 08 be 79 21 41 00 5b 5d }
        $s3 = { 55 53 48 83 ec 70 48 8d 44 24 30 48 89 44 24 10 48 8d 44 24 40 48 89 44 24 08 8b 84 24 90 00 00 00 89 04 24 e8 22 fb ff ff e8 fd 58 ff ff e8 38 5a ff ff e8 f3 59 ff ff 0f 1f 00 e8 5b 5e ff ff 48 89 c7 e8 23 5b ff ff 48 89 c7 48 89 c5 e8 18 5f ff ff 48 8d 4c 24 50 31 d2 be 6e 00 00 00 48 89 c7 48 89 c3 e8 41 59 ff ff 48 8b 7c 24 50 31 c9 ba 04 00 00 00 be 21 00 00 00 e8 1b 60 ff ff 48 8d 54 24 2f 48 8d 7c 24 60 4c 89 e6 e8 d9 5c ff ff 48 8d 7c 24 60 ba 88 f8 40 00 be a7 20 41 00 e8 a5 1f 00 00 48 8b 4c 24 60 31 d2 be 64 00 00 00 48 89 df e8 f1 58 ff ff 31 c9 31 d2 be 65 00 00 00 48 89 df e8 e0 58 ff ff 48 85 c0 7e 73 48 8b 7c 24 50 e8 41 58 ff ff 8b 54 24 30 48 8b 74 24 40 48 89 df e8 50 59 ff ff 48 8b 7c 24 40 e8 66 12 00 00 48 8b 94 24 a0 00 00 00 48 8b b4 24 98 00 00 00 48 89 df e8 0e fd ff ff 48 89 df e8 b6 5f ff ff 48 89 ef e8 ce 58 ff ff b8 01 00 00 00 48 8b 54 24 60 48 8d 7a e8 48 81 ff c0 54 61 00 75 23 48 83 c4 70 5b 5d 41 5c c3 66 0f 1f 44 00 00 48 89 df e8 80 5f ff ff 48 89 ef e8 98 58 ff ff 31 c0 eb cb be b0 32 40 00 48 8d 4f 10 48 85 f6 74 3d 83 ca ff }
        $s4 = { 8b 15 6e e4 20 00 31 ff be e0 57 61 00 e8 0a b8 ff ff 48 89 c7 31 c0 48 85 ff 74 17 48 89 3d e9 e4 20 00 e8 a4 bf ff ff 89 05 e6 e4 20 00 b8 01 00 }
        $s5 = { b8 02 00 00 00 48 89 fb 48 83 ec 10 66 89 04 25 00 00 00 00 e8 a6 4e ff ff 83 f8 ff 89 04 24 74 16 89 04 25 04 00 00 00 b8 01 00 00 00 48 83 c4 10 5b c3 0f 1f 40 00 48 89 df e8 f0 4e ff ff 48 89 c1 31 c0 48 85 }
    condition:
        uint32(0) == 0x464c457f and filesize > 30KB and 4 of them
}
