// Checked with malquery, nothing but the files are present in Hybrid Analysis, impossible to confirm, rest experimental
rule Exp_CVE_2021_40444_Sep_2021_1 {
   meta:
        description = "Detect the maldocs with a structure like used for CVE_2021_40444 exploit"
        author = "Arkbird_SOLG"
        reference1 = "-"
        date = "2021-09-09"
        hash1 = "199b9e9a7533431731fbb08ff19d437de1de6533f3ebbffc1e13eeffaa4fd455"
        hash2 = "3bddb2e1a85a9e06b9f9021ad301fdcde33e197225ae1676b8c6d0b416193ecf"
        hash3 = "5b85dbe49b8bc1e65e01414a0508329dc41dc13c92c08a4f14c71e3044b06185"
        hash4 = "938545f7bbe40738908a95da8cdeabb2a11ce2ca36b0f6a74deda9378d380a52"
        tlp = "White"
        level = "experimental"
        adversary = "-"
    strings:
        $x1 = { 2f 5f 72 65 6c 73 2f 64 6f 63 75 6d 65 6e 74 2e 78 6d 6c 2e 72 65 6c 73 55 54 09 00 03 [3] 61 [3] 61 75 78 0b 00 01 04 00 00 00 00 04 00 00 00 00 ?? 94 ?? 4e c2 [3] ef 4d 7c 87 }
        $x2 = { 77 6d 66 55 54 09 00 03 00 a6 ce 12 00 a6 ce 12 75 78 0b 00 01 04 00 00 00 00 04 00 00 00 00 bb 7e f6 d8 2c 06 38 48 00 93 85 e1 8c 0c 9c 0c 0c cc 52 60 1e 2b 98 64 01 62 66 46 0e 30 8f 9b 09 26 ce 03 66 31 83 55 00 00 50 4b 03 04 ?? 00 00 00 ?? 00 [10] 00 00 [2] 00 00 ?? 00 1c 00 }
    condition:
        uint16(0) == 0x4B50 and filesize > 5KB and all of ($x*) 
}
