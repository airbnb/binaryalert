rule MAL_ELF_Go_Worm_Jul_2021_1 {
   meta:
        description = "Detect the worm written in Go that drops XMRig Miner"
        author = "Arkbird_SOLG"
        reference1 = "https://twitter.com/IntezerLabs/status/1409844721992749059"
        reference2 = "https://twitter.com/JAMESWT_MHT/status/1409848815948111877"
        date = "2021-07-06"
        hash1 = "774ccd1281b02bc9f0c7e7185c424a42cd98bcc758c893e8a96dfb206a02fcbe"
        hash2 = "bea5a4358184555924ab6c831bf34edf279f4b93d750d5321263439dcf9c245a"
        tlp = "White"
        adversary = "-"
    strings:
        $s1 = { 57 6f 72 6b 65 72 3a 20 28 25 64 29 2c 20 43 68 65 63 6b 20 49 50 28 25 73 29 20 77 69 74 68 20 53 53 48 20 70 6f 72 74 20 69 73 20 6f 70 65 6e 2e 2e 2e }
        $s2 = { 63 61 74 20 2f 64 65 76 2f 6e 75 6c 6c 20 3e 20 7e 2f 2e 62 61 73 68 5f 68 69 73 74 6f 72 79 20 26 26 20 68 69 73 74 6f 72 79 20 2d 63 }
        $s3 = { 6e 6f 68 75 70 20 2e 2f 25 73 20 26 3e 20 6d 79 73 71 6c 6c 6f 67 73 20 26 }
        $s4 = { 72 6d 20 2d 66 20 25 73 20 6d 79 73 71 6c 6c 6f 67 73 } 
        $s5 = { 63 6f 6d 6d 61 6e 64 20 2d 76 20 62 61 73 68 }
        $s6 = { 53 74 6f 70 20 62 72 75 74 65 20 6f 6e 2c 20 57 6f 72 6b 65 72 3a 20 28 25 64 29 2c 20 54 72 79 3a 20 49 50 3a 20 25 73 2c 20 63 72 65 64 65 6e 74 69 61 6c 3a 20 25 73 2f 25 73 20 28 25 64 2f 25 64 29 3a 20 44 55 52 41 54 49 4f 4e 3a 20 25 66 }
        $s7 = { 57 6f 72 6b 65 72 3a 20 28 25 64 29 2c 20 54 72 79 3a 20 49 50 3a 20 25 73 2c 20 63 72 65 64 65 6e 74 69 61 6c 3a 20 25 73 2f 25 73 20 28 25 64 2f 25 64 29 }
    condition:
        uint32(0) == 0x464c457f and filesize > 900KB and all of ($s*) 
}
