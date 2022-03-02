rule KPortScan
{
    meta:
        id = "3ywZWmdGN5mlc73cUnzre"
        fingerprint = "ee8fb9b2387f2fe406f89b99b46f8f1b3855df23e09908c67b53c13532160915"
        version = "1.0"
        creation_date = "2020-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies KPortScan, port scanner."
        category = "MALWARE"
        malware_type = "SCANNER"

    strings:
        $s1 = "KPortScan 3.0" ascii wide
        $s2 = "KPortScan3.exe" ascii wide
        $x1 = "Count of goods:" ascii wide
        $x2 = "Current range:" ascii wide
        $x3 = "IP ranges list is clear" ascii wide
        $x4 = "ip,port,state" ascii wide
        $x5 = "on_loadFinished(QNetworkReply*)" ascii wide
        $x6 = "on_scanDiapFinished()" ascii wide
        $x7 = "on_scanFinished()" ascii wide
        $x8 = "scanDiapFinished()" ascii wide
        $x9 = "scanFinished()" ascii wide
        $x10 = "with port" ascii wide
        $x11 = "without port" ascii wide

    condition:
        any of ($s*) or 3 of ($x*)
}