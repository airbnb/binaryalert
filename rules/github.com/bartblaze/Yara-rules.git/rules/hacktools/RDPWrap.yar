rule RDPWrap
{
    meta:
        id = "5t73wrjJYkVLaE3Mn4a6sp"
        fingerprint = "f16d06fc8f81dcae5727af12a84956fc7b3c2aab120d6f4eaac097f7452e71d4"
        version = "1.0"
        creation_date = "2020-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RDP Wrapper, sometimes used by attackers to maintain persistence."
        category = "MALWARE"
        reference = "https://github.com/stascorp/rdpwrap"


    strings:
        $ = "rdpwrap.dll" ascii wide
        $ = "rdpwrap.ini" ascii wide
        $ = "RDP Wrapper" ascii wide
        $ = "RDPWInst" ascii wide
        $ = "Stas'M Corp." ascii wide
        $ = "stascorp" ascii wide

    condition:
        any of them
}