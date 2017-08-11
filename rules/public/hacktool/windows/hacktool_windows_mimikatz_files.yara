rule hacktool_windows_mimikatz_files
{
    meta:
        description = "Mimikatz credential dump tool: Files"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        md5_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        md5_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
    strings:
        $s1 = "kiwifilter.log" fullword wide
        $s2 = "kiwissp.log" fullword wide
        $s3 = "mimilib.dll" fullword ascii wide
    condition:
        any of them
}
