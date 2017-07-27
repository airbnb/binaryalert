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
        fidelity = "high"
    strings:
        $a1 = "INTERCEPTED PASSWORD:" wide ascii
        $a2 = "more sshbuf problems." wide ascii
    condition:
        all of ($a*)
}

rule macos_wirelurker
{
    meta:
        date = "2017-04-26"
        description = "Wirelurker Malware"
        reference = "https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/research/unit42-wirelurker-a-new-era-in-ios-and-os-x-malware"
        org = "Airbnb CSIRT"
        fidelity = "medium"
    strings:
        $a1 = "/usr/local/machook/" wide ascii
        $a2 = "/usr/local/Resources/start.sh" wide ascii
        $a3 = "/usr/local/Resources/FontMap1.cfg" wide ascii
        $a4 = "/Users/Shared/start.sh" nocase wide ascii
        $a5 = "com.apple.machook_damon.plist" wide ascii
        $a6 = "com.apple.globalupdate.plist" wide ascii
        $a7 = "/tmp/machook.log" wide ascii
        $n1 = "/var/db/.MRTReady" fullword wide ascii
        $n2 = "MRT.CertificateRemediation" fullword wide ascii
    condition:
        MachO and any of ($a*) and not any of ($n*)
}

rule multiOS_pupy_rat
{
    meta:
        date = "2017-05-10"
        description = "pupy - opensource cross platform rat and post-exploitation tool"
        reference = "https://github.com/n1nj4sec/pupy"
        org = "Airbnb CSIRT"
        fidelity = "high"
    strings:
        $a1 = "dumping lsa secrets" nocase wide ascii
        $a2 = "dumping cached domain passwords" nocase wide ascii
        $a3 = "the keylogger is already started" nocase wide ascii
        $a4 = "pupyutils.dns" wide ascii
        $a5 = "pupwinutils.security" wide ascii
        $a6 = "-PUPY_CONFIG_COMES_HERE-" wide ascii
    condition:
        2 of ($a*)
}

rule windows_ransomware_wannacry
{
    meta:
        date = "2017-05-12"
        description = "wannacry ransomware for windows"
        reference = "https://securelist.com/blog/incidents/78351/wannacry-ransomware-used-in-widespread-attacks-all-over-the-world/"
        org = "Airbnb CSIRT"
        md5 = "4fef5e34143e646dbf9907c4374276f5"
        fidelity = "medium"
    strings:
        // generic
        $a1 = "msg/m_chinese" wide ascii
        $a2 = ".wnry" wide ascii
        $a3 = "attrib +h" wide ascii
        // unique malware strings
        $b1 = "WNcry@2ol7" wide ascii
        // c2
        $b2 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" wide ascii
        // bitcoin addresses
        $b3 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" wide ascii
        $b4 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" wide ascii
        $b5 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" wide ascii
    condition:
        all of ($a*) or any of ($b*)
}

rule hacktool_masscan
{
    meta:
        date = "2017-07-27"
        description = "masscan is a performant port scanner, it produces results similar to nmap"
        reference = "https://github.com/robertdavidgraham/masscan"
        org = "Airbnb CSIRT"
        fidelity = "high"
    strings:
        $a1 = "EHLO masscan" fullword wide ascii
        $a2 = "User-Agent: masscan/" wide ascii
        $a3 = "/etc/masscan/masscan.conf" fullword wide ascii
        $b1 = "nmap(%s): unsupported. This code will never do DNS lookups." wide ascii
        $b2 = "nmap(%s): unsupported, we do timing WAY different than nmap" wide ascii
        $b3 = "[hint] I've got some local priv escalation 0days that might work" wide ascii
        $b4 = "[hint] VMware on Macintosh doesn't support masscan" wide ascii
    condition:
        all of ($a*) or any of ($b*)
}
