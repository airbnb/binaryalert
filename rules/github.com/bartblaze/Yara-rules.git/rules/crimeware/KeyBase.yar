rule KeyBase
{
    meta:
        id = "5cV9wZM0UzNuIyF7OK1Tpk"
        fingerprint = "d959211abb79a5b0e4e1e2e8c30bc6963876dcbe929e9099085dd2cc75dce730"
        version = "1.0"
        creation_date = "2019-02-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies KeyBase aka Kibex."
        category = "MALWARE"
        malware = "KEYBASE"
        hash = "cafe2d12fb9252925fbd1acb9b7648d6"

    strings:
        $s1 = " End:]" ascii wide
        $s2 = "Keystrokes typed:" ascii wide
        $s3 = "Machine Time:" ascii wide
        $s4 = "Text:" ascii wide
        $s5 = "Time:" ascii wide
        $s6 = "Window title:" ascii wide
        $x1 = "&application=" ascii wide
        $x2 = "&clipboardtext=" ascii wide
        $x3 = "&keystrokestyped=" ascii wide
        $x4 = "&link=" ascii wide
        $x5 = "&username=" ascii wide
        $x6 = "&windowtitle=" ascii wide
        $x7 = "=drowssap&" ascii wide
        $x8 = "=emitenihcam&" ascii wide

    condition:
        uint16(0)==0x5a4d and (5 of ($s*) or 6 of ($x*) or (3 of ($s*) and 3 of ($x*)))
}