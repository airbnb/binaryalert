rule MAL_ELF_Rekoobe_Nov_2021_1 {
    meta:
        description = "Detect the Rekoobe rootkit"
        author = "Arkbird_SOLG"
        reference ="Internal Research"
        date = "2021-11-10"
        hash1 = "bf09a1a7896e05b18c033d2d62f70ea4cac85e2d72dbd8869e12b61571c0327e"
        hash2 = "e1999a3e5a611312e16bb65bb5a880dfedbab8d4d2c0a5d3ed1ed926a3f63e94"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = { 00 ?? 19 00 00 00 48 85 c0 [2-6] bf 0a 00 00 00 e8 [2] 01 00 ?? 24 00 00 00 48 85 c0 [2-6] c6 00 48 c6 40 05 49 c6 40 01 49 c6 40 06 4c c6 40 02 53 c6 40 07 45 c6 40 03 54 c6 40 08 3d c6 40 04 46 c6 40 09 00 48 89 c7 e8 [2] 00 00 48 8d 54 24 0c }
        $s2 = "GETCONF_DIR" ascii
        $s3 = "/var/run/nscd/so/dev/ptmx" ascii 
        $s4 = { 45 78 65 63 53 74 61 72 74 3d 2f 62 69 6e 2f 62 61 73 68 20 2d 63 20 2f 75 73 72 2f 62 69 6e 2f 62 69 6f 73 65 74 64 }
        $s5 = { 48 89 df e8 [3] ff 31 f6 48 89 df e8 [3] ff 48 8d 58 01 48 }
        $s6 = { 2f 76 61 72 2f 74 6d 70 00 2f 76 61 72 2f 70 72 6f 66 69 6c 65 }
    condition:
        uint32(0) == 0x464C457F and filesize > 100KB and 5 of ($s*)
}
