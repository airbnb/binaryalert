rule DearCry
{
    meta:
        id = "6wHCvbraYF2t1m7FWnjepd"
        fingerprint = "ce3c2631969e462acd01b9dc26fd03985076add51f8478e76aca93f260a020d8"
        version = "1.0"
        creation_date = "2021-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies DearCry ransomware."
        category = "MALWARE"
        malware = "DEARCRY"
        malware_type = "RANSOMWARE"
        reference = "https://twitter.com/MsftSecIntel/status/1370236539427459076"


    strings:
        $pdb = "C:\\Users\\john\\Documents\\Visual Studio 2008\\Projects\\EncryptFile -svcV2\\Release\\EncryptFile.exe.pdb" ascii wide
        $key = {4D 49 49 42 43 41 4B 43 41 51 45 41 79 4C 42 43 6C 7A 39 68 73 46 47 52 66 39 66 6B 33 7A 30 7A 6D 59 32 72 7A 32 4A 31 
    71 71 47 66 56 34 38 44 53 6A 50 56 34 6C 63 77 6E 68 43 69 34 2F 35 2B 0A 43 36 55 73 41 68 6B 2F 64 49 34 2F 35 48 77 62 66 5A 
    42 41 69 4D 79 53 58 4E 42 33 44 78 56 42 32 68 4F 72 6A 44 6A 49 65 56 41 6B 46 6A 51 67 5A 31 39 42 2B 4B 51 46 57 6B 53 6F 31 
    75 62 65 0A 56 64 48 6A 77 64 76 37 34 65 76 45 2F 75 72 39 4C 76 39 48 4D 2B 38 39 69 5A 64 7A 45 70 56 50 4F 2B 41 6A 4F 54 74 
    73 51 67 46 4E 74 6D 56 65 63 43 32 76 6D 77 39 6D 36 30 64 67 79 52 2F 31 0A 43 4A 51 53 67 36 4D 6F 62 6C 6F 32 4E 56 46 35 30 
    41 4B 33 63 49 47 32 2F 6C 56 68 38 32 65 62 67 65 64 58 73 62 56 4A 70 6A 56 4D 63 30 33 61 54 50 57 56 34 73 4E 57 6A 54 4F 33 
    6F 2B 61 58 0A 36 5A 2B 56 47 56 4C 6A 75 76 63 70 66 4C 44 5A 62 33 74 59 70 70 6B 71 5A 7A 41 48 66 72 43 74 37 6C 56 30 71 4F
    34 37 46 56 38 73 46 43 6C 74 75 6F 4E 69 4E 47 4B 69 50 30 38 34 4B 49 37 62 0A 33 58 45 4A 65 70 62 53 4A 42 33 55 57 34 6F 34 
    43 34 7A 48 46 72 71 6D 64 79 4F 6F 55 6C 6E 71 63 51 49 42 41 77 3D 3D}

    condition:
        any of them
}