rule BazarLoader
{
    meta:
        id = "71rkxLlpnZn1Wd8IRiqeno"
        fingerprint = "3bf045c85aedaf5e7ddaba5c8d8d0054615d1e24ab40bb9ba295b04693a95b69"
        version = "1.0"
        creation_date = "2020-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies BazarLoader."
        category = "MALWARE"
        malware_type = "LOADER"
        malware = "BAZARLOADER"
        reference = "https://www.bleepingcomputer.com/news/security/bazarbackdoor-trickbot-gang-s-new-stealthy-network-hacking-malware/"


    strings:
        $code = { 4? 89 05 69 8f 03 00 4? 85 c0 0f 84 e3 fe ff ff 4? 8b 05 01 e3 02 00 4? 89 85 e0 00 00 00 4? 8b 05 fb 
    e2 02 00 4? 89 85 e8 00 00 00 4? c7 85 d0 00 00 00 0f 00 00 00 4? 89 a5 c8 00 00 00 4? 88 a5 b8 00 00 00 4? 8d 
    44 ?4 40 4? 8d 15 77 e2 02 00 4? 8d 8d b8 00 00 00 e8 ca df ff ff 90 4? c7 45 58 0f 00 00 00 4? 89 65 50 4? 88 
    65 40 4? 8d 44 ?4 07 4? 8d 15 36 e2 02 00 4? 8d 4d 40 e8 a4 df ff ff 90 4? c7 45 08 0f 00 00 00 4? 89 65 00 4? 
    88 65 f0 4? 8d 44 ?4 0b 4? 8d 15 00 e2 02 00 }
        $pdb1 = "C:\\Users\\User\\Desktop\\2010\\14.4.20\\Test_64\\SEED\\Release\\SEED.pdb" ascii wide
        $pdb2 = "D:\\projects\\source\\repos\\7\\bd7 v2\\Bin\\x64\\Release_nologs\\bd7_x64_release_nologs.pdb" ascii wide

    condition:
        $code or any of ($pdb*)
}