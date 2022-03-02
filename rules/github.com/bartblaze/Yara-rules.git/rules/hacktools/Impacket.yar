rule Impacket
{
    meta:
        id = "4slxMFaVQR9nCS6mQxIQj"
        fingerprint = "3c84db45525bc8981b832617b35c0b81193827313b23c7fede0b00badc3670f4"
        version = "1.0"
        creation_date = "2020-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Impacket, a collection of Python classes for working with network protocols."
        category = "TOOL"
        tool = "IMPACKET"
        mitre_att = "S0357"
        reference = "https://github.com/SecureAuthCorp/impacket"


    strings:
        $ = "impacket.crypto" ascii wide
        $ = "impacket.dcerpc" ascii wide
        $ = "impacket.examples" ascii wide
        $ = "impacket.hresult_errors" ascii wide
        $ = "impacket.krb5" ascii wide
        $ = "impacket.nmb" ascii wide
        $ = "impacket.nt_errors" ascii wide
        $ = "impacket.ntlm" ascii wide
        $ = "impacket.smb" ascii wide
        $ = "impacket.smb3" ascii wide
        $ = "impacket.smb3structs" ascii wide
        $ = "impacket.smbconnection" ascii wide
        $ = "impacket.spnego" ascii wide
        $ = "impacket.structure" ascii wide
        $ = "impacket.system_errors" ascii wide
        $ = "impacket.uuid" ascii wide
        $ = "impacket.version" ascii wide
        $ = "impacket.winregistry" ascii wide

    condition:
        any of them
}