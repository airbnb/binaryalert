rule APT_FIN8_BADHATCH_Mar_2021_1 {
   meta:
        description = "Detect version of BADHATCH used by FIN8 group"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-03-17"
        hash1 = "32863daa615afbb3e90e3dad35ad47199050333a2aaed57e5065131344206fe1"
        hash2 = "e058280f4b15c1be6488049e0bdba555f1baf42e139b7251d6b2c230e28e0aef"
   strings:
        $ver1 = { 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 0d 0a 2a 20 53 48 20 76 65 72 73 69 6f 6e 20 25 75 2e 25 75 20 62 75 69 6c 64 20 25 75 20 25 73 0d 0a 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 0d 0a 0d 0a } // ----------------------------------------\r\n* SH version %u.%u build %u %s\r\n----------------------------------------\r\n\r\n
        $ver2 = { 25 63 72 77 78 2d 2d 2d 2d 2d 2d 20 31 20 6f 20 67 20 25 31 36 6c 6c 69 20 25 73 20 25 32 75 20 25 34 75 20 25 53 0d 0a } // %crwx------ 1 o g %16lli %s %2u %4u %S\r\n
        // debug outputs
        $dbg1 = { 0d 0a 54 4f 4b 45 4e 20 44 4f 4d 41 49 4e 20 55 53 45 52 4e 41 4d 45 3a 20 25 53 5c 25 53 0d 0a 0d 0a } // \r\nTOKEN DOMAIN USERNAME: %S\\%S\r\n\r\n
        $dbg2 = { 48 4f 53 54 20 50 49 44 3a 20 25 64 0d 0a 50 52 4f 43 45 53 53 20 4e 41 4d 45 3a 20 25 73 0d 0a } // HOST PID: %d\r\nPROCESS NAME: %s\r\n
        $dbg3 = { 4f 53 3a 20 25 73 25 73 20 53 50 20 25 64 20 25 73 20 28 25 64 2e 25 64 2e 25 64 29 0d 0a } // OS: %s%s SP %d %s (%d.%d.%d)\r\n
        $dbg4 = { 49 4e 54 45 47 52 49 54 59 20 4c 45 56 45 4c 3a 20 25 73 0d 0a } // INTEGRITY LEVEL: %s\r\n
        $dbg5 = { 48 4f 53 54 4e 41 4d 45 3a 20 25 73 0d 0a } // HOSTNAME: %s\r\n
        $dbg6 = { 5c 5c 25 73 5c 70 69 70 65 5c [-] 00 } // \\\\%s\\pipe\\??? -> for pass the hash
        $dbg7 = { 43 4c 49 45 4e 54 20 49 44 3a 20 25 30 38 58 2d 25 30 38 58 2d 25 30 38 58 2d 25 30 38 58 2d 25 30 38 58 2d 53 48 0d 0a } // CLIENT ID: %08X-%08X-%08X-%08X-%08X-SH\r\n
        // powershell loader + pipe calls
        $power1 = "%systemroot%\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -nop -noni -ep bypass -c iex(" fullword wide
        $power2 = "[System.Convert]::FromBase64String(" fullword ascii
        $power3 = "New-Object System.IO.Pipes.PipeAccessRule((New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid,$Null)),'ReadWrite','Allow')" fullword ascii
        $power4 = "New-Object System.IO.Pipes.NamedPipeServerStream" fullword ascii
   condition:
        uint16(0) == 0x5a4d and filesize > 30KB and 1 of ($ver*) and 5 of ($dbg*) and 2 of ($power*)
}
