rule IEuser_author_doc
{
    meta:
        id = "6KWw23emrB9UUOTTLuFIe9"
        fingerprint = "08cd3ae7218fba3334965f671c82ffcda47ffe510545d7859ef66e79619a1cbe"
        version = "1.0"
        creation_date = "2020-12-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Microsoft Word documents created with the default user on IE11 test VMs, more likely to be suspicious."
        category = "MALWARE"
        reference = "https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/"


    strings:
        $doc = {D0 CF 11 E0}
        $ieuser = {49 00 45 00 55 00 73 00 65 00 72}

    condition:
        $doc at 0 and $ieuser
}