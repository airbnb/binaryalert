rule UNK_DEV_0322_Jul_2021_1 {
    meta:
        description = "Detect the script used by DEV-0322 for create a new user after exploit the CVE-2021-35211"
        author = "Arkbird_SOLG"
        reference ="https://www.cadosecurity.com/triage-analysis-of-serv-u-ftp-user-backdoor-deployed-by-cve-2021-35211/"
        date = "2021-07-16"
        hash1 = "fb101d9980ba2e22dceac7367c670b4894eaae9a8cef9de98ed85499a3b014ea"
        hash2 = "134a570f480536d04a056da99e58a3c982aa36f5b314f48a01420b66b759d35d"
        hash3 = "8785f1049eed4f837e634bf61468e6db921368b61ef5c8b4afa03f44465bd3e0"
        tlp = "white"
        adversary = "DEV-0322"
    strings:
        // ActiveX objects
        $obj1 = { 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 27 29 }
        $obj2 = { 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 }
        // Arguments for manage the service
        $arg1 = { 2d 73 74 6f 70 65 6e 67 69 6e 65 }
        $arg2 = { 2d 73 74 61 72 74 73 65 72 76 69 63 65 }
        //Strings on the command
        $s1 = { 3c 3c 2d 20 41 64 6d 69 6e 54 79 70 65 }
        $s2 = { 43 55 73 65 72 50 61 73 73 77 6f 72 64 41 74 74 72 5c 72 5c 6e 50 61 73 73 77 6f 72 64 }
        $s3 = { 3c 3c 2d 20 50 61 73 73 77 6f 72 64 43 68 61 6e 67 65 64 4f 6e 5c 72 5c 6e 43 52 68 69 6e 6f 55 69 6e 74 41 74 74 72 }
        $s4 = { 3c 3c 2d 20 49 6e 63 6c 75 64 65 52 65 73 70 43 6f 64 65 73 49 6e 4d 73 67 46 69 6c 65 73 }
    condition:
        filesize > 1KB and filesize < 15KB and all of ($obj*) and all of ($arg*) and 3 of ($s*)
}
