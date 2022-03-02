rule Ekans
{
    meta:
        id = "6Kzy2bA2Zj7kvpXriuZ14m"
        fingerprint = "396b915c02a14aa809060946c9294f487a5107ab37ebefb6d5cde07de4113d43"
        version = "1.0"
        creation_date = "2020-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Ekans aka Snake ransomware unpacked or in memory."
        category = "MALWARE"
        malware = "EKANS"
        malware_type = "RANSOMWARE"
        actor_type = "APT"
        actor = "SNAKE"
        mitre_group = "TURLA"
        mitre_att = "S0605"

    strings:
        $ = "already encrypted!" ascii wide
        $ = "cant kill process %v : %v" ascii wide
        $ = "could not access service: %v" ascii wide
        $ = "could not retrieve service status: %v" ascii wide
        $ = "could not send control=%d: %v" ascii wide
        $ = "error encrypting %v : %v" ascii wide
        $ = "faild to get process list" ascii wide
        $ = "priority files: %v" ascii wide
        $ = "priorityFiles: %v" ascii wide
        $ = "pub: %v" ascii wide
        $ = "root: %v" ascii wide
        $ = "There can be only one" ascii wide
        $ = "timeout waiting for service to go to state=%d" ascii wide
        $ = "Toatal files: %v" ascii wide
        $ = "total lengt: %v" ascii wide
        $ = "worker %s started job %s" ascii wide

    condition:
        3 of them
}