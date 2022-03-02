rule NLBrute
{
    meta:
        id = "6b1itE1MIciily5r3hEAlg"
        fingerprint = "b303f9469c58c3c8417b5825ba949adf7032192a9f29cc8346b90636dd2ca7b5"
        version = "1.0"
        creation_date = "2020-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies NLBrute, an RDP brute-forcing tool."
        category = "HACKTOOL"

    strings:
        $ = "SERVER:PORT@DOMAIN\\USER;PASSWORD" ascii wide

    condition:
        any of them
}