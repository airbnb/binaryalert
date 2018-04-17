rule eicar_av_test {
    /*
       Per standard, match only if entire file is EICAR string plus optional trailing whitespace.
       The raw EICAR string to be matched is:
       X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
    */

    meta:
        description = "This is a standard AV test, intended to verify that BinaryAlert is working correctly."
        author = "Austin Byers | Airbnb CSIRT"
        reference = "http://www.eicar.org/86-0-Intended-use.html"

    strings:
        $eicar_regex = /^X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*\s*$/

    condition:
        all of them
}

rule eicar_substring_test {
    /*
       More generic - match just the embedded EICAR string (e.g. in packed executables, PDFs, etc)
    */

    meta:
        description = "Standard AV test, checking for an EICAR substring"
        author = "Austin Byers | Airbnb CSIRT"

    strings:
        $eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

    condition:
        all of them
}