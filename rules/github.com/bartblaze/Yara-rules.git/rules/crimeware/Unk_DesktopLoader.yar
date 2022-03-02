rule Unk_DesktopLoader
{
    meta:
        id = "5XutaPgnKyd7zIb41Eqna1"
        fingerprint = "1c8def2957471e3fc4b17be9fd65466b23b8cf997f0df74fb6103f8421751a2e"
        version = "1.0"
        creation_date = "2021-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies implant that will decrypt and load shellcode from a blob file. Calling it DesktopLoader for now, based on the filename it seeks."
        category = "MALWARE"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lockfile-ransomware-new-petitpotam-windows"


    strings:
        $ = { 68 00 08 00 00 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 33 
    c9 85 c0 7e ?? ba 5c 00 00 00 8d 49 00 66 39 14 ?? ?? ?? ?? ?? 
    75 ?? 85 c9 74 ?? 49 48 85 c0 7f ?? eb ?? 33 c9 66 89 0c ?? ?? 
    ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 00 
    68 80 00 00 00 6a 03 6a 00 6a 02 68 00 00 00 80 68 ?? ?? ?? ?? 
    ff 15 ?? ?? ?? ?? 83 f8 ff 75 ?? 6a 00 ff 15 ?? ?? ?? ?? }

    condition:
        any of them
}