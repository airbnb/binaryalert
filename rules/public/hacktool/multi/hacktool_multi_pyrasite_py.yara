rule hacktool_multi_pyrasite_py
{
    meta:
        description = "A tool for injecting arbitrary code into running Python processes."
        reference = "https://github.com/lmacken/pyrasite"
        author = "@fusionrace"
    strings:
        $s1 = "WARNING: ptrace is disabled. Injection will not work." fullword ascii wide
        $s2 = "A payload that connects to a given host:port and receives commands" fullword ascii wide
        $s3 = "A reverse Python connection payload." fullword ascii wide
        $s4 = "pyrasite - inject code into a running python process" fullword ascii wide
        $s5 = "The ID of the process to inject code into" fullword ascii wide
        $s6 = "This file is part of pyrasite." fullword ascii wide
        $s7 = "https://github.com/lmacken/pyrasite" fullword ascii wide
        $s8 = "Setup a communication socket with the process by injecting" fullword ascii wide
        $s9 = "a reverse subshell and having it connect back to us." fullword ascii wide
        $s10 = "Write out a reverse python connection payload with a custom port" fullword ascii wide
        $s11 = "Wait for the injected payload to connect back to us" fullword ascii wide
        $s12 = "PyrasiteIPC" fullword ascii wide
        $s13 = "A reverse Python shell that behaves like Python interactive interpreter." fullword ascii wide
        $s14 = "pyrasite cannot establish reverse" fullword ascii wide
    condition:
        any of them
}
