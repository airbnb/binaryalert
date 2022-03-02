rule ArechClient
{
    meta:
        id = "1POsZzKWdklwDRUysnEJ9J"
        fingerprint = "949f1c6596fffe0aca581e61bcc522e70775ad16c651875539c32d6de6801729"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies ArechClient, infostealer."
        category = "MALWARE"
        malware = "ARECHCLIENT"
        malware_type = "INFOSTEALER"


    strings:
        $ = "is_secure" ascii wide
        $ = "encrypted_value" ascii wide
        $ = "host_keyexpires_utc" ascii wide

    condition:
        all of them
}