rule Webshell_in_image
{
    meta:
        id = "6IgdjyQO28avrjCjsw4VWh"
        fingerprint = "459e953dedb3a743094868b6ba551e72c3640e3f4d2d2837913e4288e88f6eca"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies a webshell or backdoor in image files."
        category = "MALWARE"
        malware_type = "WEBSHELL"

    strings:
        $gif = {47 49 46 38 3? 61}
        $png = {89 50 4E 47 0D 0A 1A 0A}
        $jpeg = {FF D8 FF E0}
        $bmp = {42 4D}
        $s1 = "<%@ Page Language=" ascii wide
        $s2 = "<?php" ascii wide nocase
        $s3 = "eval(" ascii wide nocase
        $s4 = "<eval" ascii wide nocase
        $s5 = "<%eval" ascii wide nocase

    condition:
        ($gif at 0 and any of ($s*)) or ($png at 0 and any of ($s*)) or ($jpeg at 0 and any of ($s*)) or ($bmp at 0 and any of ($s*))
}