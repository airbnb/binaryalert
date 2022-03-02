rule WinLock
{
    meta:
        id = "3MQTREUk3DgifGki8sa7hl"
        fingerprint = "6d659e5dc636a9535d07177776551ae3b32eae97b86e3e7dd01d74d0bbe33c82"
        version = "1.0"
        creation_date = "2020-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies WinLock (aka Blocker) ransomware variants generically."
        category = "MALWARE"
        malware = "WINLOCK"
        malware_type = "RANSOMWARE"

    strings:
        $s1 = "twexx32.dll" ascii wide
        $s2 = "s?cmd=ul&id=%s" ascii wide
        $s3 = "card_ukash.png" ascii wide
        $s4 = "toneo_card.png" ascii wide
        $pdb = "C:\\Kuzja 1.4\\vir.vbp" ascii wide
        $x1 = "AntiWinLockerTray.exe" ascii wide
        $x2 = "Computer name:" ascii wide
        $x3 = "Current Date:" ascii wide
        $x4 = "Information about blocking" ascii wide
        $x5 = "Key Windows:" ascii wide
        $x6 = "Password attempts:" ascii wide
        $x7 = "Registered on:" ascii wide
        $x8 = "ServiceAntiWinLocker.exe" ascii wide
        $x9 = "Time of Operation system:" ascii wide
        $x10 = "To removing the system:" ascii wide

    condition:
        3 of ($s*) or $pdb or 5 of ($x*)
}