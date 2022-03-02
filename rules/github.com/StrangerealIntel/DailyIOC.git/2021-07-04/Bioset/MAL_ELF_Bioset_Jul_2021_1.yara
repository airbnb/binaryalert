rule MAL_ELF_Bioset_Jul_2021_1 {
   meta:
        description = "Detect the Bioset malware"
        author = "Arkbird_SOLG"
        reference1 = "https://twitter.com/IntezerLabs/status/1409844721992749059"
        reference2 = "https://twitter.com/JAMESWT_MHT/status/1409848815948111877"
        date = "2021-07-02"
        hash1 = "3afe2ec273608be0b34b8b357778cc2924c344dd1b00a84cf90925eeb2469964"
        hash2 = "3de97c2b211285022a34a62b536cef586d987939d40d846930c201d010517a10"
        hash3 = "b00157dbb371e8abe19a728104404af61acc3c5d4a6f67c60e694fe0788cb491"
        hash4 = "7fa37dd67dcd04fc52787c5707cf3ee58e226b98c779feb45b78aa8a249754c7"
        hash5 = "79e93f6e5876f31ddc4a6985b290ede6a2767d9a94bdf2057d9c464999163746"
        tlp = "White"
        adversary = "-"
    strings:
        $s1 = "exec bash --login" fullword ascii
        $s2 =  { 55 48 89 e5 53 48 83 ec 48 48 89 7d b8 48 c7 45 d8 [2] 40 00 48 c7 45 d0 00 00 00 00 c7 45 e8 00 00 00 00 c7 45 ec 00 00 00 00 eb 30 48 8b 05 [2] 20 00 8b 55 ec 48 63 d2 48 c1 e2 03 48 01 d0 48 8b 00 48 89 c7 e8 ?? fa ff ff 89 c2 8b 45 e8 01 d0 83 c0 01 89 45 e8 83 45 ec 01 48 8b 05 [2] 20 00 8b 55 ec 48 63 d2 48 c1 e2 03 48 01 d0 48 8b 00 48 85 c0 75 b4 48 8b 05 [2] 20 00 8b 55 ec 48 63 d2 48 c1 e2 03 48 83 ea 08 48 01 d0 48 8b 18 48 8b 05 [2] 20 00 8b 55 ec 48 63 d2 48 c1 e2 03 48 83 ea 08 48 01 d0 48 8b 00 48 89 c7 e8 ?? fa ff ff 48 83 c0 01 48 01 d8 48 89 45 d0 8b 45 e8 48 98 48 89 c7 e8 ?? fb ff ff 48 89 45 e0 c7 45 ec 00 00 00 00 eb 74 48 8b 05 [2] 20 00 8b 55 ec 48 63 d2 48 c1 e2 03 48 01 d0 48 8b 10 48 8b 45 e0 48 89 d6 48 89 c7 e8 ?? f9 ff ff 48 8b 05 [2] 20 00 8b 55 ec 48 63 d2 48 c1 e2 03 48 01 d0 48 8b 00 48 89 c7 e8 ?? f9 ff ff 89 45 cc 8b 45 cc 48 98 48 83 c0 01 48 01 45 e0 48 8b 05 [2] 20 00 8b 55 ec 48 63 d2 48 c1 e2 03 48 01 c2 48 8b 45 e0 48 89 02 83 45 ec 01 48 8b 05 [2] 20 00 8b 55 ec 48 63 d2 48 c1 e2 03 48 01 d0 48 8b 00 }
        $s3 = "amcsh_connect" fullword ascii
        $s4 = "GOT HAHA: %d" fullword ascii
        $s5 = { 52 65 63 76 65 64 20 74 65 72 6d 20 65 6e 76 20 76 61 72 3a 20 25 73 00 77 69 6e 3a 25 64 2c 25 64 }
        $s6 = { 55 48 89 e5 48 81 ec f0 20 00 00 89 bd 1c df ff ff 48 c7 45 f0 [2] 40 00 48 8d 85 20 df ff ff be 01 20 00 00 48 89 c7 e8 ?? fa ff ff 48 8d b5 28 ff ff ff 48 8d 85 2c ff ff ff 41 b8 00 00 00 00 b9 00 00 00 00 ba 00 00 00 00 48 89 c7 e8 ?? fa ff ff 85 c0 79 2a e8 ?? f8 ff ff 8b 00 89 c7 e8 ?? fa ff ff 48 89 c6 bf [2] 40 00 b8 00 00 00 00 e8 26 fc ff ff b8 01 00 00 00 e9 f8 05 00 00 8b 85 28 ff ff ff 89 c7 e8 ?? fa ff ff 48 89 45 e8 48 83 7d e8 00 75 0a b8 01 00 00 00 e9 d6 05 00 00 bf [2] 40 00 e8 ?? f9 ff ff 48 8d 95 20 df ff ff 8b 85 1c df ff ff 48 89 d6 89 c7 e8 ?? 17 00 00 89 45 fc 83 7d fc 00 79 2a e8 [2] ff ff 8b 00 89 c7 e8 ?? fa ff ff 48 89 c6 bf [2] 40 00 b8 00 00 00 00 e8 b0 fb ff ff }
        $s7 = { 8b 45 fc 48 63 d0 8b 85 2c ff ff ff 48 8d 8d 20 df ff ff 48 89 ce 89 c7 e8 ?? f3 ff ff 89 45 fc 8b 45 fc 89 c6 bf [2] 40 00 b8 00 00 00 00 e8 f0 f6 ff ff 83 7d fc }
        $s8 = { 55 48 89 e5 53 48 81 ec e8 00 00 00 48 89 b5 48 ff ff ff 48 89 95 50 ff ff ff 48 89 8d 58 ff ff ff 4c 89 85 60 ff ff ff 4c 89 8d 68 ff ff ff 84 c0 74 23 0f 29 85 70 ff ff ff 0f 29 4d 80 0f 29 55 90 0f 29 5d a0 0f 29 65 b0 0f 29 6d c0 0f 29 75 d0 0f 29 7d e0 48 89 bd 18 ff ff ff 48 8b 05 [2] 20 00 48 85 c0 75 16 be [2] 40 00 bf [2] 40 00 e8 ?? fd ff ff 48 89 05 [2] 20 00 c7 85 20 ff ff ff 08 00 00 00 c7 85 24 ff ff ff 30 00 00 00 48 8d 45 10 48 89 85 28 ff ff ff 48 8d 85 40 ff ff ff 48 89 85 30 ff ff ff 48 8b 05 [2] 20 00 48 8d 95 20 ff ff ff 48 8b 8d 18 ff ff ff 48 89 ce 48 89 c7 e8 ?? fd ff ff 48 c7 85 38 ff ff ff [2] 40 00 48 8b 1d [2] 20 00 48 8b 85 38 ff ff ff 48 89 c7 e8 ?? fb ff ff 48 89 c6 48 8b 85 38 ff ff ff 48 89 d9 ba 01 00 00 00 48 89 c7 e8 ?? fd ff ff 48 8b 05 [2] 20 00 48 89 c7 e8 ?? fc ff ff 48 81 c4 e8 00 00 00 5b }
    condition:
        uint32(0) == 0x464c457f and filesize > 10KB and 6 of ($s*) 
}
