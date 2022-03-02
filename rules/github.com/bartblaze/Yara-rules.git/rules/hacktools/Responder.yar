rule Responder
{
    meta:
        id = "542DKcb5v7CRu4SFgfHBAj"
        fingerprint = "5ae4386a4f020726581f7d0082f15bf6f412c7e5db79904663a2f2d4ac5a1a58"
        version = "1.0"
        creation_date = "2020-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Responder, an LLMNR, NBT-NS and MDNS poisoner."
        category = "HACKTOOL"
        tool = "RESPONDER"
        mitre_att = "S0174"
        reference = "https://github.com/lgandx/Responder"


    strings:
        $ = "[*] [LLMNR]" ascii wide
        $ = "[*] [NBT-NS]" ascii wide
        $ = "[*] [MDNS]" ascii wide
        $ = "[FINGER] OS Version" ascii wide
        $ = "[FINGER] Client Version" ascii wide
        $ = "serve_thread_udp_broadcast" ascii wide
        $ = "serve_thread_tcp_auth" ascii wide
        $ = "serve_NBTNS_poisoner" ascii wide
        $ = "serve_MDNS_poisoner" ascii wide
        $ = "serve_LLMNR_poisoner" ascii wide
        $ = "poisoners.LLMNR " ascii wide
        $ = "poisoners.NBTNS" ascii wide
        $ = "poisoners.MDNS" ascii wide

    condition:
        any of them
}