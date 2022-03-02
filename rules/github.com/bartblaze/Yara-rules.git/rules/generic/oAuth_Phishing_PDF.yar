rule oAuth_Phishing_PDF
{
    meta:
        id = "789YmThaTvLDaE1V2Oqx7q"
        fingerprint = "c367bca866de0b066e291b4e45216cbb68cc23297b002a29ca3c8d640a7db78e"
        version = "1.0"
        creation_date = "2022-01-01"
        first_imported = "2022-02-03"
        last_modified = "2022-02-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies potential phishing PDFs that target oAuth."
        category = "MALWARE"
        reference = "https://twitter.com/ffforward/status/1484127442679836676"

    strings:
        $pdf = {25504446} //%PDF
        $s1 = "/URI (https://login.microsoftonline.com/common/oauth2/" ascii wide nocase
        $s2 = "/URI (https://login.microsoftonline.com/consumers/oauth2" ascii wide nocase
        $s3 = "/URI (https://accounts.google.com/o/oauth2" ascii wide nocase

    condition:
        $pdf at 0 and any of ($s*)
}
