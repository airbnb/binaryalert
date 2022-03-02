rule XiaoBa
{
    meta:
        id = "7HQbk7TyDS3DhwWOktZe9t"
        fingerprint = "d41a019709801bbbc4284b27fd7f582ed1db624415cb28b88a7cdf5b0c3331b2"
        version = "1.0"
        creation_date = "2019-09-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies XiaoBa ransomware unpacked or in memory."
        category = "MALWARE"
        malware = "XIAOBA"
        malware_type = "RANSOMWARE"

    strings:
        $ = "BY:TIANGE" ascii wide
        $ = "Your disk have a lock" ascii wide
        $ = "Please enter the unlock password" ascii wide
        $ = "Please input the unlock password" ascii wide
        $ = "I am very sorry that all your files have been encrypted" ascii wide

    condition:
        any of them
}