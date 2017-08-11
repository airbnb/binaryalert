rule hacktool_windows_mimikatz_errors
{
    meta:
        description = "Mimikatz credential dump tool: Error messages"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        md5_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        md5_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
    strings:
        $s1 = "[ERROR] [LSA] Symbols" fullword ascii wide
        $s2 = "[ERROR] [CRYPTO] Acquire keys" fullword ascii wide
        $s3 = "[ERROR] [CRYPTO] Symbols" fullword ascii wide
        $s4 = "[ERROR] [CRYPTO] Init" fullword ascii wide
    condition:
        all of them
}
