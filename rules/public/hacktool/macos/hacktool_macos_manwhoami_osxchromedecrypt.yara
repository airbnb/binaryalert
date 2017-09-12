rule hacktool_macos_manwhoami_osxchromedecrypt
{
    meta:
        description = "Decrypt Google Chrome / Chromium passwords and credit cards on macOS / OS X."
        reference = "https://github.com/manwhoami/OSXChromeDecrypt"
        author = "@mimeframe"
    strings:
        $a1 = "Credit Cards for Chrome Profile" wide ascii
        $a2 = "Passwords for Chrome Profile" wide ascii
        $a3 = "Unknown Card Issuer" wide ascii
        $a4 = "ERROR getting Chrome Safe Storage Key" wide ascii
        $b1 = "select name_on_card, card_number_encrypted, expiration_month, expiration_year from credit_cards" wide ascii
        $b2 = "select username_value, password_value, origin_url, submit_element from logins" wide ascii
    condition:
        3 of ($a*) or all of ($b*)
}
