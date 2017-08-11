rule hacktool_multi_jtesta_ssh_mitm
{
    meta:
        description = "intercepts ssh connections to capture credentials"
        reference = "https://github.com/jtesta/ssh-mitm"
        author = "@fusionrace"
    strings:
        $a1 = "INTERCEPTED PASSWORD:" wide ascii
        $a2 = "more sshbuf problems." wide ascii
    condition:
        all of ($a*)
}
