rule hacktool_windows_hot_potato
{
    meta:
        description = "https://foxglovesecurity.com/2016/01/16/hot-potato/"
        reference = "https://github.com/foxglovesec/Potato"
        author = "@mimeframe"
    strings:
        $a1 = "Parsing initial NTLM auth..." wide ascii
        $a2 = "Got PROPFIND for /test..." wide ascii
        $a3 = "Starting NBNS spoofer..." wide ascii
        $a4 = "Exhausting UDP source ports so DNS lookups will fail..." wide ascii
        $a5 = "Usage: potato.exe -ip" wide ascii
    condition:
        any of ($a*)
}
