rule hacktool_windows_mimikatz_modules
{
    meta:
        description = "Mimikatz credential dump tool: Modules"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        md5_1 = "0c87c0ca04f0ab626b5137409dded15ac66c058be6df09e22a636cc2bcb021b8"
        md5_2 = "0c91f4ca25aedf306d68edaea63b84efec0385321eacf25419a3050f2394ee3b"
        md5_3 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        md5_4 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
        md5_5 = "0fee62bae204cf89d954d2cbf82a76b771744b981aef4c651caab43436b5a143"
    strings:
        $s1 = "mimilib" fullword ascii wide
        $s2 = "mimidrv" fullword ascii wide
        $s3 = "mimilove" fullword ascii wide
    condition:
        any of them
}
