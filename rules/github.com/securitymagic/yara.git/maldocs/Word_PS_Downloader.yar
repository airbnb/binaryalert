/*
    Suspicious Powershell in weaponized word documents
    Reference: 5c6148619abb10bb3789dcfb32f759a6
*/
rule suspicious_powershell_winword
{
    strings:
        $a = {D0 CF 11 E0 A1 B1 1A E1 00 00 00 00 00}
        $b = {4D 69 63 72 6F 73 6F 66 74 20 4F 66 66 69 63 65 20 57 6F 72 64 00}
        $c = "powershell -e" nocase
    condition:
        all of them
}
