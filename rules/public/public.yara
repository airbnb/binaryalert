import "pe"

private rule MachO
{
    meta:
        description = "Mach-O binaries"
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca
}

rule hacktool_mimikatz_sekurlsa
{
    meta:
        date = "2017-06-22"
        description = "Mimikatz credential dump tool"
        reference = "https://github.com/gentilkiwi/mimikatz"
        org = "Airbnb CSIRT"
        SHA256_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        SHA256_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
        fidelity = "high"
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

rule jtesta_ssh_mitm
{
    meta:
        description = "intercepts ssh connections to capture credentials"
        reference = "https://github.com/jtesta/ssh-mitm"
        org = "Airbnb CSIRT"
        date = "2017-05-19"
    strings:
        $a1 = "INTERCEPTED PASSWORD:" wide ascii
        $a2 = "more sshbuf problems." wide ascii
    condition:
        any of ($a*)
}

rule macos_wirelurker
{
    meta:
        date = "2017-04-26"
        description = "Wirelurker Malware"
        reference = "https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/research/unit42-wirelurker-a-new-era-in-ios-and-os-x-malware"
        org = "Airbnb CSIRT"
    strings:
        $a1 = "/usr/local/machook/" nocase wide ascii
        $a2 = "/usr/local/Resources/start.sh" nocase wide ascii
        $a3 = "/usr/local/Resources/FontMap1.cfg" nocase wide ascii
        $a4 = "/Users/Shared/start.sh" nocase wide ascii
        $a5 = "com.apple.machook_damon.plist" nocase wide ascii
        $a6 = "com.apple.globalupdate.plist" nocase wide ascii
        $a7 = ".comeinbaby.com/" nocase wide ascii
        $a8 = "/tmp/machook.log" nocase wide ascii
    condition:
        MachO and any of ($a*)
}

rule multiOS_pupy_rat
{
    meta:
        date = "2017-05-10"
        description = "pupy - opensource cross platform rat and post-exploitation tool"
        reference = "https://github.com/n1nj4sec/pupy"
        org = "Airbnb CSIRT"
    strings:
        $a1 = "dumping lsa secrets"  nocase wide ascii
        $a2 = "dumping cached domain passwords"  nocase wide ascii
        $a3 = "the keylogger is already started" nocase wide ascii
        $a4 = "pupyutils.dns" nocase wide ascii
        $a5 = "pupwinutils.security" nocase wide ascii
        $a6 = "-PUPY_CONFIG_COMES_HERE-" nocase wide ascii
    condition:
        any of ($a*)
}

rule windows_ransomware_wannacry
{
    meta:
        date = "2017-05-12"
        description = "wannacry ransomware for windows"
        reference = "https://securelist.com/blog/incidents/78351/wannacry-ransomware-used-in-widespread-attacks-all-over-the-world/"
        org = "Airbnb CSIRT"
        md5 = "4fef5e34143e646dbf9907c4374276f5"
    strings:
        // generic
        $a1 = "msg/m_chinese" nocase wide ascii
        $a2 = ".wnry" nocase wide ascii
        $a3 = "attrib +h" nocase wide ascii
        // unique malware strings
        $b1 = "WNcry@2ol7" nocase wide ascii
        // c2
        $b2 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" nocase wide ascii
        // bitcoin addresses
        $b3 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" nocase wide ascii
        $b4 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" nocase wide ascii
        $b5 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" nocase wide ascii
    condition:
        all of ($a*) or any of ($b*)
}
