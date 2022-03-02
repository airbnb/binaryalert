rule Jupyter
{
    meta:
        id = "5yGlzHFZQ1qvusLOwAt8UQ"
        fingerprint = "0c7ba0956c611a1e56ce972b4362f7f0f56bd2bd61ce78bee4adeb0a69e548c4"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Jupyter aka SolarMarker, backdoor."
        category = "MALWARE"
        malware = "SOLARMARKER"
        malware_type = "BACKDOOR"

    strings:
        $ = "var __addr__=" ascii wide
        $ = "var __hwid__=" ascii wide
        $ = "var __xkey__=" ascii wide
        $ = "solarmarker.dat" ascii wide

    condition:
        3 of them
}