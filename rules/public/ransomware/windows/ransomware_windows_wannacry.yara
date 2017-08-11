rule ransomware_windows_wannacry
{
    meta:
        description = "wannacry ransomware for windows"
        reference = "https://securelist.com/blog/incidents/78351/wannacry-ransomware-used-in-widespread-attacks-all-over-the-world/"
        author = "@fusionrace"
        md5 = "4fef5e34143e646dbf9907c4374276f5"
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
