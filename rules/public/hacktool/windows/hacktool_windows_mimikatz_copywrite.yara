rule hacktool_windows_mimikatz_copywrite
{
    meta:
        description = "Mimikatz credential dump tool: Author copywrite"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        md5_1 = "0c87c0ca04f0ab626b5137409dded15ac66c058be6df09e22a636cc2bcb021b8"
        md5_2 = "0c91f4ca25aedf306d68edaea63b84efec0385321eacf25419a3050f2394ee3b"
        md5_3 = "0fee62bae204cf89d954d2cbf82a76b771744b981aef4c651caab43436b5a143"
        md5_4 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
        md5_5 = "09c542ff784bf98b2c4899900d4e699c5b2e2619a4c5eff68f6add14c74444ca"
        md5_6 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
    strings:
        $s1 = "Kiwi en C" fullword ascii wide
        $s2 = "Benjamin DELPY `gentilkiwi`" fullword ascii wide
        $s3 = "http://blog.gentilkiwi.com/mimikatz" fullword ascii wide
        $s4 = "Build with love for POC only" fullword ascii wide
        $s5 = "gentilkiwi (Benjamin DELPY)" fullword wide
        $s6 = "KiwiSSP" fullword wide
        $s7 = "Kiwi Security Support Provider" fullword wide
        $s8 = "kiwi flavor !" fullword wide
    condition:
        any of them
}
