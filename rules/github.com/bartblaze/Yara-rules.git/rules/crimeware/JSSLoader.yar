rule JSSLoader
{
    meta:
        id = "4kX6atSwDdjKnsiSNAVeZ2"
        fingerprint = "6c73b4052e8493cd64cae3794c3ebb92cb95f64dd5224326b1ca45aecd7cb6da"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies FIN7's JSSLoader."
        category = "MALWARE"
        malware = "JSSLOADER"
        malware_type = "LOADER"
        mitre_att = "S0648"

    strings:
        $s1 = "host" ascii wide fullword
        $s2 = "domain" ascii wide fullword
        $s3 = "user" ascii wide fullword
        $s4 = "processes" ascii wide fullword
        $s5 = "name" ascii wide fullword
        $s6 = "pid" ascii wide fullword
        $s7 = "desktop_file_list" ascii wide fullword
        $s8 = "file" ascii wide fullword
        $s9 = "size" ascii wide fullword
        $s10 = "adinfo" ascii wide fullword
        $s11 = "no_ad" ascii wide fullword
        $s12 = "adinformation" ascii wide fullword
        $s13 = "part_of_domain" ascii wide fullword
        $s14 = "pc_domain" ascii wide fullword
        $s15 = "pc_dns_host_name" ascii wide fullword
        $s16 = "pc_model" ascii wide fullword
        $x1 = "/?id=" ascii wide
        $x2 = "failed start exe" ascii wide
        $x3 = "Sending timer request failed, error code" ascii wide
        $x4 = "Internet connection failed, error code" ascii wide
        $x5 = "Sending initial request failed, error code" ascii wide

    condition:
        14 of ($s*) or 3 of ($x*)
}