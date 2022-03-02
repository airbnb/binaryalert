rule OLEfile_in_CAD_FAS_LSP
{
    meta:
        id = "3Ie7cdUdqnv46f0qtY5cfU"
        fingerprint = "178edb2c2d85cc62b6c89ef84044df6631889869b56a5cbb6162ba7fa62939a3"
        version = "1.0"
        creation_date = "2019-12-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies OLE files embedded in AutoCAD and related Autodesk files, quite uncommon and potentially malicious."
        category = "MALWARE"
        reference = "https://blog.didierstevens.com/2019/12/16/analyzing-dwg-files-with-vba-macros/"


    strings:
        $acad = {41 43 31}
        $fas = {0D 0A 20 46 41 53 34 2D 46 49 4C 45 20 3B 20 44 6F 20 6E 6F 74 20 63 68 61 6E 67 65 20 69 74 21}
        $lsp1 = "lspfilelist"
        $lsp2 = "setq"
        $lsp3 = ".lsp"
        $lsp4 = "acad.mnl"
        $ole = {D0 CF 11 E0}

    condition:
        ($acad at 0 and $ole) or ($fas at 0 and $ole) or (( all of ($lsp*)) and $ole)
}