rule Generic_Phishing_PDF
{
    meta:
        id = "6iE0XEqqhVGNED6Z8xIMr1"
        fingerprint = "f3f31ec9651ee41552d41dbd6650899d7a33beea46ed1c3329c3bbd023fe128e"
        version = "1.0"
        creation_date = "2019-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies generic phishing PDFs."
        category = "MALWARE"
        reference = "https://bartblaze.blogspot.com/2019/03/analysing-massive-office-365-phishing.html"


    strings:
        $pdf = {25504446}
        $s1 = "<xmp:CreatorTool>RAD PDF</xmp:CreatorTool>"
        $s2 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"DynaPDF"

    condition:
        $pdf at 0 and all of ($s*)
}