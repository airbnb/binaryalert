rule EXP_CVE_2021_42321_Nov_2021_1 {
    meta:
        description = "Detect CVE-2021-42321 exploit tool"
        author = "Arkbird_SOLG"
        reference ="https://gist.github.com/testanull/0188c1ae847f37a70fe536123d14f398"
        date = "2021-11-21"
        hash1 = "537744916ce2e78748d301901c679307e8159101f3b194add89f6e1dfbf62c32"
        tlp = "white"
        level = "Experimental"
        adversary = "-"
    strings:
        $s1 = { 41 41 45 41 41 41 44 2f 2f 2f 2f 2f 41 51 41 41 41 41 41 41 41 41 41 4d 41 67 41 41 41 46 35 4e 61 57 4e 79 62 }
        $s2 = "/ews/exchange.asmx" ascii
        $s3 = { 48 74 74 70 4e 74 6c 6d 41 75 74 68 28 27 25 73 27 20 25 20 28 55 53 45 52 29 }
        $s4 = { 22 55 73 65 72 2d 41 67 65 6e 74 22 3a 20 22 45 78 63 68 61 6e 67 65 53 65 72 76 69 63 65 73 43 6c 69 65 6e 74 }
        $s5 = { 6d 56 6a 64 45 52 68 64 47 46 51 63 6d 39 32 61 57 52 6c 63 6a 34 4e 43 69 41 67 49 43 41 38 54 32 4a 71 5a 57 4e 30 52 47 46 30 59 56 42 79 62 33 5a 70 5a 47 56 79 49 48 67 36 53 32 56 35 50 53 4a 7a 5a 58 52 4e 5a 58 52 6f 62 32 51 69 49 45 39 69 61 6d 56 6a 64 45 6c 75 63 33 52 68 62 6d 4e 6c 50 53 4a 37 65 44 70 54 64 47 46 30 61 57 4d 67 59 7a 70 44 62 32 35 6d 61 57 64 31 63 6d 46 30 61 57 }
    condition:
        filesize > 3KB and 4 of them
}
