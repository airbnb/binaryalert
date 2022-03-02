rule Exp_Underminer_Apr_2021_1
{
    meta:
        description = "Detect Underminer exploit kit"
        author = "Arkbird_SOLG"
        date = "2021-04-14"
        reference = "https://twitter.com/nao_sec/status/1382358986813415427"
        hash1 = "172ac73cda6260918510ad2f4481a7fcd90c5a86d47dd880c5bcb3596dd20a7d"
    strings:
        $s1 = { 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 53 68 6f 63 6b 77 61 76 65 46 6c 61 73 68 2e 53 68 6f 63 6b 77 61 76 65 46 6c 61 73 68 22 29 } // new ActiveXObject("ShockwaveFlash.ShockwaveFlash")
        $s2 = "$version" fullword ascii
        $s3 = { 6e 61 76 69 67 61 74 6f 72 2e 70 6c 75 67 69 6e 73 26 26 6e 61 76 69 67 61 74 6f 72 2e 70 6c 75 67 69 6e 73 2e 6c 65 6e 67 74 68 3e 30 } // navigator.plugins&&navigator.plugins.length>0
        $s4 = { 6e 61 76 69 67 61 74 6f 72 2e 70 6c 75 67 69 6e 73 5b 22 53 68 6f 63 6b 77 61 76 65 20 46 6c 61 73 68 22 5d } // navigator.plugins["Shockwave Flash"]
        $s5 = { 63 6c 61 73 73 69 64 3d 27 63 6c 73 69 64 3a 44 32 37 43 44 42 36 45 2d 41 45 36 44 2d 31 31 63 66 2d 39 36 42 38 2d 34 34 34 35 35 33 35 34 30 30 30 30 27 } // classid='clsid:D27CDB6E-AE6D-11cf-96B8-444553540000'
        $s6 = { 22 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 73 68 6f 63 6b 77 61 76 65 2d 66 6c 61 73 68 22 } // "application/x-shockwave-flash"
        $s7 = { 22 64 61 74 61 22 2c 22 2f 6c 6f 67 6f 2e 73 77 66 22 } // "data","/logo.swf"
        $s8 = { 22 30 30 30 30 30 30 30 30 22 2b 28 [1-8] 5b 30 5d 3e 3e 3e 30 29 2e 74 6f 53 74 72 69 6e 67 28 31 36 29 29 2e 73 6c 69 63 65 28 2d 38 29 2b 28 22 30 30 30 30 30 30 30 30 22 2b 28 [1-8] 5b 31 5d 3e 3e 3e 30 29 2e 74 6f 53 74 72 69 6e 67 28 31 36 29 29 2e 73 6c 69 63 65 28 2d 38 29 } // "00000000"+([...][0]>>>0).toString(16)).slice(-8)+("00000000"+([...][1]>>>0).toString(16)).slice(-8)
    condition:
        filesize > 5KB and 6 of ($s*) 
} 
