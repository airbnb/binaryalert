rule APT_SideWinder_Nov_2020_1 { 
 meta: 
    description = "Detect Sidewinder DLL decoder algorithm" 
    author = "Arkbird_SOLG"
    reference = "https://twitter.com/hexfati/status/1325397305051148292"
    date = "2020-11-14"
    hash1 = "8d7ad2c603211a67bb7abf2a9fe65aefc993987dc804bf19bafbefaaca066eaa"
strings: 
    $s = { 13 30 05 00 ?? 00 00 00 01 00 00 11 ?? ?? 00 00 ?? ?? ?? 00 00 [30-80] 2B 16 07 08 8F 1? } 
condition: 
    uint16(0) == 0x5a4d and filesize > 3KB and $s
}

