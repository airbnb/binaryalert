rule wannaren_ransomware {

    meta:

        description = "Rule to detect WannaRen Ransomware"
        author = "McAfee ATR Team"
        date = "2020-04-25"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/WannaRen"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://blog.360totalsecurity.com/en/attention-you-may-have-become-a-susceptible-group-of-wannaren-ransomware/"
        hash = "7b364f1c854e6891c8d09766bcc9a49420e0b5b4084d74aa331ae94e2cfb7e1d"
        
    strings:

        $sq0 = { 92 93 a91c2ea521 59 334826 }
        $sq1 = { d0ce 6641 c1e9c0 41 80f652 49 c1f94d }
        $sq2 = { 80f8b5 4d 63c9 f9 4d 03d9 41 }
        $sq3 = { 34b7 d2ea 660fbafa56 0f99c2 32d8 660fbafaed 99 }
        $sq4 = { f9 f7c70012355f 35c01f5226 f9 8d8056c800b0 f6c4b2 f9 }
        $sq5 = { f5 f9 44 3aeb 45 33cd 41 }
        $sq6 = { 890f c0ff12 44 b4a3 ee 2b4e70 7361 }
        $sq7 = { 81c502000000 6689542500 6681d97a1e 660fabe1 660fbae1a5 8b0f 8dbf04000000 }
        $sq8 = { 8d13 de11 d7 677846 f1 0d8cd45f87 bb34b98f33 }
        $sq9 = { 1440 4b 41 e8???????? 397c0847 }

    condition:

        uint16(0) == 0x5a4d and
        filesize < 21000KB and
        7 of them
}
