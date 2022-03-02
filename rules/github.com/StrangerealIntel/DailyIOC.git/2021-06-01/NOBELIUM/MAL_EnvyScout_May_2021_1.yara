rule MAL_EnvyScout_May_2021_1 {
   meta:
        description = "Detect EnvyScout downloader"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-05-28"
        hash1 = "279d5ef8f80aba530aaac8afd049fa171704fc703d9cfe337b56639732e8ce11"
        hash2 = "9059c5b46dce8595fcc46e63e4ffbceeed883b7b1c9a2313f7208a7f26a0c186"
        tlp = "White"
        adversary = "NOBELIUM"
   strings:      
        $s1 = "==typeof window&&window.window===window?window:" fullword ascii
        $s2 = "==typeof self&&self.self===self?self:" fullword ascii
        $s3 = "0===t?t={autoBom:!1}:" fullword ascii
        $s4 = "_global.saveAs=saveAs.saveAs=saveAs" fullword ascii
        $s5 = "navigator.userAgent" fullword ascii
        $s6 = { 6e 65 77 20 42 6c 6f 62 28 5b [1-12] 5d 2c 20 7b 74 79 70 65 3a 20 22 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d 22 7d 29 3b 73 61 76 65 41 73 28 }
   condition:
        filesize > 100KB and 5 of ($s*)
}
