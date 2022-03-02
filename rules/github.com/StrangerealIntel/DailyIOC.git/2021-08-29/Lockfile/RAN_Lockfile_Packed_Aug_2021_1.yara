rule RAN_Lockfile_Packed_Aug_2021_1 {
   meta:
        description = "Detect lockfile ransomware (Packed version)"
        author = "Arkbird_SOLG"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lockfile-ransomware-new-petitpotam-windows"
        date = "2021-08-28"
        hash1 = "2a23fac4cfa697cc738d633ec00f3fbe93ba22d2498f14dea08983026fdf128a"
        hash2 = "bf315c9c064b887ee3276e1342d43637d8c0e067260946db45942f39b970d7ce"
        level = "Experimental"
        adversary = "Lockfile"
   strings:
        $s1 = { 90 03 ?? 40 58 4a bc 3c 64 e4 5d 2e 44 45 45 45 ?? 72 48 8e 45 45 43 45 [6] 08 f6 33 45 [5] 01 e9 e3 }
        $s2 = { 5b 22 48 0f 5b 22 48 0f 5b 22 48 bb c7 d3 48 03 5b 22 48 bb c7 d1 48 97 5b 22 48 bb c7 d0 48 16 5b 22 48 69 34 df 48 0e 5b 22 48 5d 2e 26 49 1d 5b 22 48 5d 2e 21 49 05 5b 22 48 59 2e 27 49 28 5b 22 48 59 2e 21 49 0e 5b 22 48 5d 2e 27 49 58 5b 22 48 06 23 b1 48 02 5b 22 48 0f 5b 23 48 bf 5b 22 48 59 2e 2b 49 0d 5b 22 48 59 2e dd 48 0e 5b 22 48 59 2e 20 49 0e 5b 22 48 52 69 63 68 0f 5b 22 48 }
        $s3 = { 44 fc 90 a9 [0-4] 1c 79 38 10 [0-4] 18 20 72 0e [2-5] 3f [0-4] 24 34 6c 05 fc [0-4] 23 40 }
        $s4 = { c3 df [0-4] 10 4c c8 20 d3 55 56 57 41 54 41 55 }
   condition:
        uint16(0) == 0x5a4d and filesize > 10KB and all of ($s*)
}
