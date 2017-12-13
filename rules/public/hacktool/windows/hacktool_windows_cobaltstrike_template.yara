private rule cobaltstrike_template_exe
{
    meta:
        description = "Template to provide executable detection Cobalt Strike payloads"
        reference = "https://www.cobaltstrike.com"
        author = "@javutin, @joseselvi"
    strings:
        $compiler = "mingw-w64 runtime failure" nocase

        $f1 = "VirtualQuery"   fullword
        $f2 = "VirtualProtect" fullword
        $f3 = "vfprintf"       fullword
        $f4 = "Sleep"          fullword
        $f5 = "GetTickCount"   fullword

        $c1 = { // Compare case insensitive with "msvcrt", char by char
                0f b6 50 01 80 fa 53 74 05 80 fa 73 75 42 0f b6
                50 02 80 fa 56 74 05 80 fa 76 75 34 0f b6 50 03
                80 fa 43 74 05 80 fa 63 75 26 0f b6 50 04 80 fa
                52 74 05 80 fa 72 75 18 0f b6 50 05 80 fa 54 74
        }
    condition:
        uint16(0) == 0x5a4d and
        filesize < 1000KB and
        $compiler and
        all of ($f*) and
        all of ($c*)
}    