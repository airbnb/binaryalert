rule Specialist_Repack_Doc
{
    meta:
        id = "5kJT4oOJwT8lbgHDb9e8Cw"
        fingerprint = "0cc8378c4bca64dae2268f62576408b652014280adaeddfa9e02d3a91f26f1b9"
        version = "1.0"
        creation_date = "2022-01-01"
        first_imported = "2022-01-24"
        last_modified = "2022-01-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Office documents created by a cracked Office version, SPecialiST RePack."
        category = "MALWARE"
        reference = "https://twitter.com/malwrhunterteam/status/1483132689586831365"

    strings:
        $ = "SPecialiST RePack" ascii wide
        $ = {53 50 65 63 69 61 6C 69 53 54 20 52 65 50 61 63 6B}

    condition:
        any of them
}
