rule android_flubot {
    meta:
        author = "Thomas Barabosch, Telekom Security"
        version = "20210720"
        description = "matches on dumped, decrypted V/DEX files of Flubot version > 4.2"
        sample = "37be18494cd03ea70a1fdd6270cef6e3"

    strings:
        $dex = "dex"
        $vdex = "vdex"
        $s1 = "LAYOUT_MANAGER_CONSTRUCTOR_SIGNATURE"
        $s2 = "java/net/HttpURLConnection;"
        $s3 = "java/security/spec/X509EncodedKeySpec;"
        $s4 = "MANUFACTURER"

    condition:
        ($dex at 0 or $vdex at 0)
        and 3 of ($s*)
}
