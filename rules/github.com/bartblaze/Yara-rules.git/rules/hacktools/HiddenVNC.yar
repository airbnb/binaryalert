import "pe"

rule HiddenVNC
{
    meta:
        id = "15zXm5IVJkjh5ERo8y3PsR"
        fingerprint = "4910c9889e5940a74cb40eab4738c519c045a4ffa48fbb69c175e65421e86563"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies HiddenVNC, which can start remote sessions."
        category = "MALWARE"
        mitre_att = "T1021.005"

    strings:
        $ = "#hvnc" ascii wide
        $ = "VNC is starting your browser..." ascii wide
        $ = "HvncAction" ascii wide
        $ = "HvncCommunication" ascii wide
        $ = "hvncDesktop" ascii wide

    condition:
        2 of them or (pe.exports("VncStartServer") and pe.exports("VncStopServer"))
}