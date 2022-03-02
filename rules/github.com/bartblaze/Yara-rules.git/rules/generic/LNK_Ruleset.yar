import "math"

private rule isLNK
{
    meta:
        id = "1XKPrHhGUVGxZ9ZtveVhF9"
        fingerprint = "399c994f697568637efb30910b80f5ae7bedd42bf1cf4188cb74610e46cb23a8"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Private rule identifying shortcut (LNK) files. To be used in conjunction with the other LNK rules below."
        category = "MALWARE"

    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }

    condition:
        $lnk at 0
}

rule PS_in_LNK
{
    meta:
        id = "5PjnTrwMNGYdZahLd6yrPa"
        fingerprint = "d89b0413d59b57e5177261530ed1fb60f0f6078951a928caf11b2db1c2ec5109"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PowerShell artefacts in shortcut (LNK) files."
        category = "MALWARE"

    strings:
        $ = ".ps1" ascii wide nocase
        $ = "powershell" ascii wide nocase
        $ = "invoke" ascii wide nocase
        $ = "[Convert]" ascii wide nocase
        $ = "FromBase" ascii wide nocase
        $ = "-exec" ascii wide nocase
        $ = "-nop" ascii wide nocase
        $ = "-noni" ascii wide nocase
        $ = "-w hidden" ascii wide nocase
        $ = "-enc" ascii wide nocase
        $ = "-decode" ascii wide nocase
        $ = "bypass" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Script_in_LNK
{
    meta:
        id = "24OwxeALdNyMpIq2oeeatL"
        fingerprint = "bed7b00cdd2966629d9492097d357b729212d6d90251b9f1319634af05f40fdc"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies scripting artefacts in shortcut (LNK) files."
        category = "MALWARE"

    strings:
        $ = "javascript" ascii wide nocase
        $ = "jscript" ascii wide nocase
        $ = "vbscript" ascii wide nocase
        $ = "wscript" ascii wide nocase
        $ = "cscript" ascii wide nocase
        $ = ".js" ascii wide nocase
        $ = ".vb" ascii wide nocase
        $ = ".wsc" ascii wide nocase
        $ = ".wsh" ascii wide nocase
        $ = ".wsf" ascii wide nocase
        $ = ".sct" ascii wide nocase
        $ = ".cmd" ascii wide nocase
        $ = ".hta" ascii wide nocase
        $ = ".bat" ascii wide nocase
        $ = "ActiveXObject" ascii wide nocase
        $ = "eval" ascii wide nocase

    condition:
        isLNK and any of them
}

rule EXE_in_LNK
{
    meta:
        id = "3SSZmnnXU0l4qoc9wubdhN"
        fingerprint = "f169fab39da34f827cdff5ee022374f7c1cc0b171da9c2bb718d8fee9657d7a3"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies executable artefacts in shortcut (LNK) files."
        category = "MALWARE"

    strings:
        $ = ".exe" ascii wide nocase
        $ = ".dll" ascii wide nocase
        $ = ".scr" ascii wide nocase
        $ = ".pif" ascii wide nocase
        $ = "This program" ascii wide nocase
        $ = "TVqQAA" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Archive_in_LNK
{
    meta:
        id = "2ku4ClpAScswD86dAiYijX"
        fingerprint = "91946edcd14021c70c3dc4e1898b346f671095e87715df73fa4db3a70074b918"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies archive (compressed) files in shortcut (LNK) files."
        category = "MALWARE"

    strings:
        $ = ".7z" ascii wide nocase
        $ = ".zip" ascii wide nocase
        $ = ".cab" ascii wide nocase
        $ = ".iso" ascii wide nocase
        $ = ".rar" ascii wide nocase
        $ = ".bz2" ascii wide nocase
        $ = ".tar" ascii wide nocase
        $ = ".lzh" ascii wide nocase
        $ = ".dat" ascii wide nocase
        $ = "WinRAR\\Rar.exe" ascii wide nocase
        $ = "expand" ascii wide nocase
        $ = "makecab" ascii wide nocase
        $ = "UEsDBA" ascii wide nocase
        $ = "TVNDRg" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Execution_in_LNK
{
    meta:
        id = "77XnooZUMUCCdEuppmQ0My"
        fingerprint = "cf4910d057f099ef2d2b6fc80739a41e3594c500e6b4eca0fc8f64e48f6dcefb"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies execution artefacts in shortcut (LNK) files."
        category = "MALWARE"

    strings:
        $ = "cmd.exe" ascii wide nocase
        $ = "/c echo" ascii wide nocase
        $ = "/c start" ascii wide nocase
        $ = "/c set" ascii wide nocase
        $ = "%COMSPEC%" ascii wide nocase
        $ = "rundll32.exe" ascii wide nocase
        $ = "regsvr32.exe" ascii wide nocase
        $ = "Assembly.Load" ascii wide nocase
        $ = "[Reflection.Assembly]::Load" ascii wide nocase
        $ = "process call" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Compilation_in_LNK
{
    meta:
        id = "6MFIj6PnQMhnF21XItMr42"
        fingerprint = "58d09c8cd94f0d8616d16195bd7fa0335657dd87235e204d49979785cdd8007e"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies compilation artefacts in shortcut (LNK) files."
        category = "MALWARE"

    strings:
        $ = "vbc.exe" ascii wide nocase
        $ = "csc.exe" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Download_in_LNK
{
    meta:
        id = "4oUWRvBhzXFLJVKxasN6Cd"
        fingerprint = "9b95b86b48df38523f1e382483c7a7fd96da1a0244b5ebdd2327eaf904afd117"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies download artefacts in shortcut (LNK) files."
        category = "MALWARE"

    strings:
        $ = "bitsadmin" ascii wide nocase
        $ = "certutil" ascii wide nocase
        $ = "ServerXMLHTTP" ascii wide nocase
        $ = "http" ascii wide nocase
        $ = "ftp" ascii wide nocase
        $ = ".url" ascii wide nocase

    condition:
        isLNK and any of them
}

rule MSOffice_in_LNK
{
    meta:
        id = "5wsZnuCXdcxZ1DbLHFC4pX"
        fingerprint = "ac2e453ed19a4f30f17a1c7ff4c8dfcd00b2c2fc53c7ab05d32f5e6a91326da1"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Microsoft Office artefacts in shortcut (LNK) files."
        category = "MALWARE"

    strings:
        $ = "winword" ascii wide nocase
        $ = "excel" ascii wide nocase
        $ = "powerpnt" ascii wide nocase
        $ = ".rtf" ascii wide nocase
        $ = ".doc" ascii wide nocase
        $ = ".dot" ascii wide nocase
        $ = ".xls" ascii wide nocase
        $ = ".xla" ascii wide nocase
        $ = ".csv" ascii wide nocase
        $ = ".ppt" ascii wide nocase
        $ = ".pps" ascii wide nocase
        $ = ".xml" ascii wide nocase

    condition:
        isLNK and any of them
}

rule PDF_in_LNK
{
    meta:
        id = "7U50CQK54jXHGYojYg4wKe"
        fingerprint = "5640fd2e7a31adf7f080658f07084d5e7b9dd89d2e58c49ffd7fe50f16bfcaa2"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Adobe Acrobat artefacts in shortcut (LNK) files."
        category = "MALWARE"

    strings:
        $ = ".pdf" ascii wide nocase
        $ = "%PDF" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Flash_in_LNK
{
    meta:
        id = "2onsBjSNyoLIP4WLOVgS56"
        fingerprint = "4d47314dce183d422d05f220835a28920f06caf8fa54c62e2427938ca68627f3"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Adobe Flash artefacts in shortcut (LNK) files."
        category = "MALWARE"

    strings:
        $ = ".swf" ascii wide nocase
        $ = ".fws" ascii wide nocase

    condition:
        isLNK and any of them
}

rule SMB_in_LNK
{
    meta:
        id = "5jhrc6f5nuBGClq72MwVw5"
        fingerprint = "530336ad2ab3fadb07e5f6517b0ac435a0e0b88a47226e5bbf43b5bcc9a79176"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SMB (share) artefacts in shortcut (LNK) files."
        category = "MALWARE"

    strings:
        $ = "\\c$\\" ascii wide nocase

    condition:
        isLNK and any of them
}


rule Long_RelativePath_LNK
{
    meta:
        id = "2ogEIXl8u2qUbIgxTmruYX"
        fingerprint = "4b822248bade98d0528ab13549797c225784d7f953fe9c14d178c9d530fb3e55"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file with a long relative path. Might be used in an attempt to hide the path."
        category = "MALWARE"

    strings:
        $ = "..\\..\\..\\..\\" ascii wide nocase

    condition:
        isLNK and any of them
}

rule Large_filesize_LNK
{
    meta:
        id = "2N6jerukOyU2qFFtcMtnWt"
        fingerprint = "a8168e65294bfc0b9ffca544891b818b37feb5b780ab357efbb56638c6578242"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file larger than 100KB. Most goodware LNK files are smaller than 100KB."
        category = "MALWARE"

    condition:
        isLNK and filesize >100KB
}

rule High_Entropy_LNK
{
    meta:
        id = "6Dqf8gBGF21dKt03BJOXbQ"
        fingerprint = "d0b5bdad04d5894cd1136ec57bd6410180923e9267edb932c8dca6ef3a23722d"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies shortcut (LNK) file with equal or higher entropy than 6.5. Most goodware LNK files have a low entropy, lower than 6."
        category = "MALWARE"

    condition:
        isLNK and math.entropy(0, filesize )>=6.5
}

rule CDN_in_LNK
{
    meta:
        id = "q22YL1ZnAbHqVNq9Iz1Bn"
        fingerprint = "81b8267b7286f4baa02c533c7a4f17e17b38859a81cc0186b1b47c89498b6a0e"
        version = "1.0"
        creation_date = "2020-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies CDN (Content Delivery Network) domain in shortcut (LNK) file."
        category = "MALWARE"

    strings:
        $ = "cdn." ascii wide nocase
        $ = "githubusercontent" ascii wide nocase
        $ = "googleusercontent" ascii wide nocase
        $ = "cloudfront" ascii wide nocase
        $ = "amazonaws" ascii wide nocase
        $ = "akamai" ascii wide nocase
        $ = "cdn77" ascii wide nocase
        $ = "discordapp" ascii wide nocase

    condition:
        isLNK and any of them
}
