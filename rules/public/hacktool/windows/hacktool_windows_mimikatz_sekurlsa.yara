rule hacktool_windows_mimikatz_sekurlsa
{
    meta:
        description = "Mimikatz credential dump tool"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        SHA256_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        SHA256_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
    strings:
        $s1 = "dpapisrv!g_MasterKeyCacheList" fullword ascii wide
        $s2 = "lsasrv!g_MasterKeyCacheList" fullword ascii wide
        $s3 = "!SspCredentialList" ascii wide
        $s4 = "livessp!LiveGlobalLogonSessionList" fullword ascii wide
        $s5 = "wdigest!l_LogSessList" fullword ascii wide
        $s6 = "tspkg!TSGlobalCredTable" fullword ascii wide
    condition:
        all of them
}
