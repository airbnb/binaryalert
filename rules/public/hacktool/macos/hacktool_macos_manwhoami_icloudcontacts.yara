rule hacktool_macos_manwhoami_icloudcontacts
{
    meta:
        description = "Pulls iCloud Contacts for an account. No dependencies. No user notification."
        reference = "https://github.com/manwhoami/iCloudContacts"
        author = "@mimeframe"
    strings:
        $a1 = "https://setup.icloud.com/setup/authenticate/" wide ascii
        $a2 = "https://p04-contacts.icloud.com/" wide ascii
        $a3 = "HTTP Error 401: Unauthorized. Are you sure the credentials are correct?" wide ascii
        $a4 = "HTTP Error 404: URL not found. Did you enter a username?" wide ascii
    condition:
        3 of ($a*)
}
