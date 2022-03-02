rule PK_Globalsources_Machine : Globalsources
{
    meta:
        description = "Phishing Kit impersonating GlobalSources"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-10"
        comment = "Phishing Kit - Globalsources - 'Scripted by Machine'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "GlobalSources"
        // specific file found in PhishingKit
        $spec_file = "index.html"
        $spec_file2 = "logo.jpg"
        $spec_file3 = "verify.php"
        $spec_file4 = "ray.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and
	    $spec_file4
}

