rule rdp_enable_multiple_sessions: capability hacktool
{
     meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
        description = "Enable RDP/Multiple User Sessions"
        date = "2022-01-14"
        reference = "https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-localsessionmanager-fdenytsconnections"
        reference2 = "https://serverfault.com/questions/822503/enable-rdp-for-multiple-sessions-command-line-option"
     strings:
        $a = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide
        $b = "fDenyTSConnections" ascii wide
        $c = "fSingleSessionPerUser" ascii wide
     condition:
        ($a and $b) or ($a and $c)
}

rule rdp_change_port_number: capability hacktool
{
     meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
        description = "Change RDP port number"
        date = "2022-01-14"
        reference = "https://helgeklein.com/blog/programmatically-determining-terminal-server-mode-on-windows-server-2008/"
     strings:
        $a = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii wide
        $b = "PortNumber"
     condition:
        all of them
}

rule allow_rdp_session_without_password: capability hacktool
{
    meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
    	description = "Remote Desktop Connection without password, e.g. seen in SDBBot / TA505"
        date = "2022-01-14"
        reference = "https://www.speedguide.net/faq/how-to-connect-using-remote-desktop-without-a-password-435"
    strings:
		$a = "LimitBlankPasswordUse" ascii wide
    condition:
    	$a
}

rule get_windows_proxy_configuration: capability hacktool
{
    meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
    	description = "Queries Windows Registry for proxy configuration"
        date = "2022-01-14"
        reference = "https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-ie-clientnetworkprotocolimplementation-hklmproxyserver"
    strings:
		$a = "Software\\Microsoft\\Windows\\Currentversion\\Internet Settings" ascii wide
		$b = "ProxyEnable" ascii wide
		$c = "ProxyServer" ascii wide
    condition:
    	all of them
}

rule cn_utf8_windows_terminal: capability hacktool
{
    meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
    	description = "This is a (dirty) hack to display UTF-8 on Windows command prompt."
        date = "2022-01-14"
        reference = "https://dev.to/mattn/please-stop-hack-chcp-65001-27db"
        reference2 = "https://www.bitdefender.com/files/News/CaseStudies/study/401/Bitdefender-PR-Whitepaper-FIN8-creat5619-en-EN.pdf"
    strings:
		$a = "chcp 65001" ascii wide
    condition:
    	$a
}

rule potential_termserv_dll_replacement: capability hacktool
{
    meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
    	description = "May replace termserv.dll to allow for multiple RDP sessions"
        date = "2022-01-14"
        reference = "https://www.mysysadmintips.com/windows/clients/545-multiple-rdp-remote-desktop-sessions-in-windows-10"
    strings:
		$a = "termsrv.dll" ascii wide
    condition:
    	$a
}
