rule LNKR_JS_a
{
    meta:
        id = "2ptjcpBqa9yDFmKpt0AW5C"
        fingerprint = "371d54a77d89c53acc9135095361279f9ecd479ec403f6a14bc393ec0032901b"
        version = "1.0"
        creation_date = "2021-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
        category = "MALWARE"
        malware_type = "ADWARE"

    strings:
        $ = "AMZN_SEARCH" ascii wide
        $ = "BANNER_LOAD" ascii wide
        $ = "CB_FSI_ANSWER" ascii wide
        $ = "CB_FSI_BLIND_NO_URL" ascii wide
        $ = "CB_FSI_BREAK" ascii wide
        $ = "CB_FSI_DISPLAY" ascii wide
        $ = "CB_FSI_DO_BLIND" ascii wide
        $ = "CB_FSI_ERROR_EXCEPTION" ascii wide
        $ = "CB_FSI_ERROR_PARSERESULT" ascii wide
        $ = "CB_FSI_ERROR_TIMEOUT" ascii wide
        $ = "CB_FSI_ERR_INVRELINDEX" ascii wide
        $ = "CB_FSI_ERR_INV_BLIND_POS" ascii wide
        $ = "CB_FSI_FUSEARCH" ascii wide
        $ = "CB_FSI_FUSEARCH_ORGANIC" ascii wide
        $ = "CB_FSI_INJECT_EMPTY" ascii wide
        $ = "CB_FSI_OPEN" ascii wide
        $ = "CB_FSI_OPTOUTED" ascii wide
        $ = "CB_FSI_OPTOUT_DO" ascii wide
        $ = "CB_FSI_ORGANIC_RESULT" ascii wide
        $ = "CB_FSI_ORGANIC_SHOW" ascii wide
        $ = "CB_FSI_ORGREDIR" ascii wide
        $ = "CB_FSI_SKIP" ascii wide
        $ = "MNTZ_INJECT" ascii wide
        $ = "MNTZ_LOADED" ascii wide
        $ = "OPTOUT_SHOW" ascii wide
        $ = "PROMO_ANLZ" ascii wide
        $ = "URL_IGNOREDOMAIN" ascii wide
        $ = "URL_STATICFILE" ascii wide

    condition:
        5 of them
}

rule LNKR_JS_b
{
    meta:
        id = "FooEUkiF1qekRyatQeewJ"
        fingerprint = "bcc81d81472d21d4fdbd10f7713c77e7246b07644abf5c2a0c8e26bf3a2d2865"
        version = "1.0"
        creation_date = "2021-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
        category = "MALWARE"
        malware_type = "ADWARE"

    strings:
        $ = "StartAll ok" ascii wide
        $ = "dexscriptid" ascii wide
        $ = "dexscriptpopup" ascii wide
        $ = "rid=LAUNCHED" ascii wide

    condition:
        3 of them
}

rule LNKR_JS_c
{
    meta:
        id = "1QAyO1czEHnDRAk825ZUFn"
        fingerprint = "9c839a66b2212d9ae94cd4ccd0150ff1c9c34d3fa797f015afa742407a7f4d4b"
        version = "1.0"
        creation_date = "2021-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
        category = "MALWARE"
        malware_type = "ADWARE"

    strings:
        $ = "var affid" ascii wide
        $ = "var alsotry_enabled" ascii wide
        $ = "var boot_time" ascii wide
        $ = "var checkinc" ascii wide
        $ = "var dom" ascii wide
        $ = "var fsgroup" ascii wide
        $ = "var gcheckrunning" ascii wide
        $ = "var kodom" ascii wide
        $ = "var last_keywords" ascii wide
        $ = "var trkid" ascii wide
        $ = "var uid" ascii wide
        $ = "var wcleared" ascii wide

    condition:
        3 of them
}

rule LNKR_JS_d
{
    meta:
        id = "ixfWYGMOBADN6j1c4HrnP"
        fingerprint = "ea7abac4ced554a26930c025a84bc5188eb195f2b3488628063f0be35c937a59"
        version = "1.0"
        creation_date = "2021-04-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
        category = "MALWARE"
        malware_type = "ADWARE"

    strings:
        $ = "adTrack" ascii wide
        $ = "addFSBeacon" ascii wide
        $ = "addYBeacon" ascii wide
        $ = "algopopunder" ascii wide
        $ = "applyAdDesign" ascii wide
        $ = "applyGoogleDesign" ascii wide
        $ = "deleteElement" ascii wide
        $ = "fixmargin" ascii wide
        $ = "galgpop" ascii wide
        $ = "getCurrentKw" ascii wide
        $ = "getGoogleListing" ascii wide
        $ = "getParameterByName" ascii wide
        $ = "getXDomainRequest" ascii wide
        $ = "googlecheck" ascii wide
        $ = "hasGoogleListing" ascii wide
        $ = "insertAfter" ascii wide
        $ = "insertNext" ascii wide
        $ = "insertinto" ascii wide
        $ = "isGoogleNewDesign" ascii wide
        $ = "moreReq" ascii wide
        $ = "openInNewTab" ascii wide
        $ = "pagesurf" ascii wide
        $ = "replaceRel" ascii wide
        $ = "sendData" ascii wide
        $ = "sizeinc" ascii wide
        $ = "streamAds" ascii wide
        $ = "urlcleanup" ascii wide

    condition:
        10 of them
}