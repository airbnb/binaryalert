import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_GENRansomware {
    meta:
        description = "detects command variations typically used by ransomware"
        author = "ditekSHen"
    strings:
        $cmd1 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii wide nocase
        $cmd2 = "vssadmin.exe Delete Shadows /all" ascii wide nocase
        $cmd3 = "Delete Shadows /all" ascii wide nocase
        $cmd4 = "} recoveryenabled no" ascii wide nocase
        $cmd5 = "} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $cmd6 = "wmic SHADOWCOPY DELETE" ascii wide nocase
        $cmd7 = "\\Microsoft\\Windows\\SystemRestore\\SR\" /disable" ascii wide nocase
        $cmd8 = "resize shadowstorage /for=c: /on=c: /maxsize=" ascii wide nocase
        $cmd9 = "shadowcopy where \"ID='%s'\" delete" ascii wide nocase
        $cmd10 = "wmic.exe SHADOWCOPY /nointeractive" ascii wide nocase
        $cmd11 = "WMIC.exe shadowcopy delete" ascii wide nocase
        $cmd12 = "Win32_Shadowcopy | ForEach-Object {$_.Delete();}" ascii wide nocase
        $delr = /del \/s \/f \/q(( [A-Za-z]:\\(\*\.|[Bb]ackup))(VHD|bac|bak|wbcat|bkf)?)+/ ascii wide
        $wp1 = "delete catalog -quiet" ascii wide nocase
        $wp2 = "wbadmin delete backup" ascii wide nocase
        $wp3 = "delete systemstatebackup" ascii wide nocase
    condition:
        (uint16(0) == 0x5a4d and 2 of ($cmd*) or (1 of ($cmd*) and 1 of ($wp*)) or #delr > 4) or (4 of them)
}

rule INDICATOR_SUSPICIOUS_ReflectiveLoader {
    meta:
        description = "detects Reflective DLL injection artifacts"
        author = "ditekSHen"
    strings:
        $s1 = "_ReflectiveLoader@" ascii wide
        $s2 = "ReflectiveLoader@" ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of them or (
            pe.exports("ReflectiveLoader@4") or
            pe.exports("_ReflectiveLoader@4") or
            pe.exports("ReflectiveLoader")
            )
        )
}

rule INDICATOR_SUSPICIOUS_IMG_Embedded_Archive {
    meta:
        description = "Detects images embedding archives. Observed in TheRat RAT."
        author = "ditekSHen"
    strings:
        $sevenzip1 = { 37 7a bc af 27 1c 00 04 } // 7ZIP, regardless of password-protection
        $sevenzip2 = { 37 e4 53 96 c9 db d6 07 } // 7ZIP zisofs compression format    
        $zipwopass = { 50 4b 03 04 14 00 00 00 } // None password-protected PKZIP
        $zipwipass = { 50 4b 03 04 33 00 01 00 } // Password-protected PKZIP
        $zippkfile = { 50 4b 03 04 0a 00 02 00 } // PKZIP
        $rarheade1 = { 52 61 72 21 1a 07 01 00 } // RARv4
        $rarheade2 = { 52 65 74 75 72 6e 2d 50 } // RARv5
        $rarheade3 = { 52 61 72 21 1a 07 00 cf } // RAR
        $mscabinet = { 4d 53 46 54 02 00 01 00 } // Microsoft cabinet file
        $zlockproe = { 50 4b 03 04 14 00 01 00 } // ZLock Pro encrypted ZIP
        $winzip    = { 57 69 6E 5A 69 70 }       // WinZip compressed archive 
        $pklite    = { 50 4B 4C 49 54 45 }       // PKLITE compressed ZIP archive
        $pksfx     = { 50 4B 53 70 58 }          // PKSFX self-extracting executable compressed file
    condition:
        // JPEG or JFIF or PNG or BMP
        (uint32(0) == 0xe0ffd8ff or uint32(0) == 0x474e5089 or uint16(0) == 0x4d42) and 1 of them
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_EventViewer {
    meta:
        description = "detects Windows exceutables potentially bypassing UAC using eventvwr.exe"
        author = "ditekSHen"
    strings:
        $s1 = "\\Classes\\mscfile\\shell\\open\\command" ascii wide nocase
        $s2 = "eventvwr.exe" ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CleanMgr {
    meta:
        description = "detects Windows exceutables potentially bypassing UAC using cleanmgr.exe"
        author = "ditekSHen"
    strings:
        $s1 = "\\Enviroment\\windir" ascii wide nocase
        $s2 = "\\system32\\cleanmgr.exe" ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_Enable_OfficeMacro {
    meta:
        description = "Detects Windows executables referencing Office macro registry keys. Observed modifying Office configurations via the registy to enable macros"
        author = "ditekSHen"
    strings:
        $s1 = "\\Word\\Security\\VBAWarnings" ascii wide
        $s2 = "\\PowerPoint\\Security\\VBAWarnings" ascii wide
        $s3 = "\\Excel\\Security\\VBAWarnings" ascii wide

        $h1 = "5c576f72645c53656375726974795c5642415761726e696e6773" nocase ascii wide
        $h2 = "5c506f776572506f696e745c53656375726974795c5642415761726e696e6773" nocase ascii wide
        $h3 = "5c5c457863656c5c5c53656375726974795c5c5642415761726e696e6773" nocase ascii wide

        $d1 = "5c%57%6f%72%64%5c%53%65%63%75%72%69%74%79%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
        $d2 = "5c%50%6f%77%65%72%50%6f%69%6e%74%5c%53%65%63%75%72%69%74%79%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
        $d3 = "5c%5c%45%78%63%65%6c%5c%5c%53%65%63%75%72%69%74%79%5c%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or 2 of ($h*) or 2 of ($d*))
}

rule INDICATOR_SUSPICIOUS_EXE_Disable_OfficeProtectedView {
    meta:
        description = "Detects Windows executables referencing Office ProtectedView registry keys. Observed modifying Office configurations via the registy to disable ProtectedView"
        author = "ditekSHen"
    strings:
        $s1 = "\\Security\\ProtectedView\\DisableInternetFilesInPV" ascii wide
        $s2 = "\\Security\\ProtectedView\\DisableAttachementsInPV" ascii wide
        $s3 = "\\Security\\ProtectedView\\DisableUnsafeLocationsInPV" ascii wide

        $h1 = "5c53656375726974795c50726f746563746564566965775c44697361626c65496e7465726e657446696c6573496e5056" nocase ascii wide
        $h2 = "5c53656375726974795c50726f746563746564566965775c44697361626c65417474616368656d656e7473496e5056" nocase ascii wide
        $h3 = "5c53656375726974795c50726f746563746564566965775c44697361626c65556e736166654c6f636174696f6e73496e5056" nocase ascii wide

        $d1 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%49%6e%74%65%72%6e%65%74%46%69%6c%65%73%49%6e%50%56" nocase ascii
        $d2 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%41%74%74%61%63%68%65%6d%65%6e%74%73%49%6e%50%56" nocase ascii
        $d3 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%55%6e%73%61%66%65%4c%6f%63%61%74%69%6f%6e%73%49%6e%50%56" nocase ascii
    condition:
         uint16(0) == 0x5a4d and (2 of ($s*) or 2 of ($h*) or 2 of ($d*))
}

rule INDICATOR_SUSPICIOUS_EXE_SandboxProductID {
    meta:
        description = "Detects binaries and memory artifcats referencing sandbox product IDs"
        author = "ditekSHen"
    strings:
        $id1 = "76487-337-8429955-22614" fullword ascii wide // Anubis Sandbox
        $id2 = "76487-644-3177037-23510" fullword ascii wide // CW Sandbox
        $id3 = "55274-640-2673064-23950" fullword ascii wide // Joe Sandbox
        $id4 = "76487-640-1457236-23837" fullword ascii wide // Anubis Sandbox
        $id5 = "76497-640-6308873-23835" fullword ascii wide // CWSandbox
        $id6 = "76487-640-1464517-23259" fullword ascii wide // ??
        $id7 = "76487 - 337 - 8429955 - 22614" fullword ascii wide // Anubis Sandbox
        $id8 = "76487 - 644 - 3177037 - 23510" fullword ascii wide // CW Sandbox
        $id9 = "55274 - 640 - 2673064 - 23950" fullword ascii wide // Joe Sandbox
        $id10 = "76487 - 640 - 1457236 - 23837" fullword ascii wide // Anubis Sandbox
        $id11 = "76497 - 640 - 6308873 - 23835" fullword ascii wide // CWSandbox
        $id12 = "76487 - 640 - 1464517 - 23259" fullword ascii wide // ??
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_SUSPICIOUS_EXE_SandboxHookingDLL {
    meta:
        description = "Detects binaries and memory artifcats referencing sandbox DLLs typically observed in sandbox evasion"
        author = "ditekSHen"
    strings:
        $dll1 = "sbiedll.dll" nocase fullword ascii wide 
        //$dll2 = "dbghelp.dll" nocase fullword ascii wide  
        $dll3 = "api_log.dll" nocase fullword ascii wide  
        $dll4 = "pstorec.dll" nocase fullword ascii wide  
        $dll5 = "dir_watch.dll" nocase fullword ascii wide
        $dll6 = "vmcheck.dll" nocase fullword ascii wide  
        $dll7 = "wpespy.dll" nocase fullword ascii wide   
        $dll8 = "SxIn.dll" nocase fullword ascii wide     
        $dll9 = "Sf2.dll" nocase fullword ascii wide     
        $dll10 = "deploy.dll" nocase fullword ascii wide   
        $dll11 = "avcuf32.dll" nocase fullword ascii wide  
        $dll12 = "BgAgent.dll" nocase fullword ascii wide  
        $dll13 = "guard32.dll" nocase fullword ascii wide  
        $dll14 = "wl_hook.dll" nocase fullword ascii wide  
        $dll15 = "QOEHook.dll" nocase fullword ascii wide  
        $dll16 = "a2hooks32.dll" nocase fullword ascii wide
        $dll17 = "tracer.dll" nocase fullword ascii wide
        $dll18 = "APIOverride.dll" nocase fullword ascii wide
        $dll19 = "NtHookEngine.dll" nocase fullword ascii wide
        $dll20 = "LOG_API.DLL" nocase fullword ascii wide
        $dll21 = "LOG_API32.DLL" nocase fullword ascii wide
        $dll22 = "vmcheck32.dll" nocase ascii wide
        $dll23 = "vmcheck64.dll" nocase ascii wide
        $dll24 = "cuckoomon.dll" nocase ascii wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_AHK_Downloader {
    meta:
        description = "Detects AutoHotKey binaries acting as second stage droppers"
        author = "ditekSHen"
    strings:
        $d1 = "URLDownloadToFile, http" ascii
        $d2 = "URLDownloadToFile, file" ascii
        $s1 = ">AUTOHOTKEY SCRIPT<" fullword wide
        $s2 = "open \"%s\" alias AHK_PlayMe" fullword wide
        $s3 = /AHK\s(Keybd|Mouse)/ fullword wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($d*) and 1 of ($s*))
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCOM {
    meta:
        description = "Detects Windows exceutables bypassing UAC using CMSTP COM interfaces. MITRE (T1218.003)"
        author = "ditekSHen"
    strings:
        // CMSTPLUA
        $guid1 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide nocase
        // CMLUAUTIL
        $guid2 = "{3E000D72-A845-4CD9-BD83-80C07C3B881F}" ascii wide nocase
        // Connection Manager LUA Host Object
        $guid3 = "{BA126F01-2166-11D1-B1D0-00805FC1270E}" ascii wide nocase
        $s1 = "CoGetObject" fullword ascii wide
        $s2 = "Elevation:Administrator!new:" fullword ascii wide
    condition:
       uint16(0) == 0x5a4d and (1 of ($guid*) and 1 of ($s*))
}

rule INDICATOR_SUSPICOUS_EXE_References_VEEAM {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing many references to VEEAM. Observed in ransomware"
    strings:
        $s1 = "VeeamNFSSvc" ascii wide nocase
        $s2 = "VeeamRESTSvc" ascii wide nocase
        $s3 = "VeeamCloudSvc" ascii wide nocase
        $s4 = "VeeamMountSvc" ascii wide nocase
        $s5 = "VeeamBackupSvc" ascii wide nocase
        $s6 = "VeeamBrokerSvc" ascii wide nocase
        $s7 = "VeeamDeploySvc" ascii wide nocase
        $s8 = "VeeamCatalogSvc" ascii wide nocase
        $s9 = "VeeamTransportSvc" ascii wide nocase
        $s10 = "VeeamDeploymentService" ascii wide nocase
        $s11 = "VeeamHvIntegrationSvc" ascii wide nocase
        $s12 = "VeeamEnterpriseManagerSvc" ascii wide nocase
        $s13 = "\"Veeam Backup Catalog Data Service\"" ascii wide nocase
        $e1 = "veeam.backup.agent.configurationservice.exe" ascii wide nocase
        $e2 = "veeam.backup.brokerservice.exe" ascii wide nocase
        $e3 = "veeam.backup.catalogdataservice.exe" ascii wide nocase
        $e4 = "veeam.backup.cloudservice.exe" ascii wide nocase
        $e5 = "veeam.backup.externalinfrastructure.dbprovider.exe" ascii wide nocase
        $e6 = "veeam.backup.manager.exe" ascii wide nocase
        $e7 = "veeam.backup.mountservice.exe" ascii wide nocase
        $e8 = "veeam.backup.service.exe" ascii wide nocase
        $e9 = "veeam.backup.uiserver.exe" ascii wide nocase
        $e10 = "veeam.backup.wmiserver.exe" ascii wide nocase
        $e11 = "veeamdeploymentsvc.exe" ascii wide nocase
        $e12 = "veeamfilesysvsssvc.exe" ascii wide nocase
        $e13 = "veeam.guest.interaction.proxy.exe" ascii wide nocase
        $e14 = "veeamnfssvc.exe" ascii wide nocase
        $e15 = "veeamtransportsvc.exe" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_Binary_References_Browsers {
    meta:
        description = "Detects binaries (Windows and macOS) referencing many web browsers. Observed in information stealers."
        author = "ditekSHen"
    strings:
        $s1 = "Uran\\User Data" nocase ascii wide
        $s2 = "Amigo\\User Data" nocase ascii wide
        $s3 = "Torch\\User Data" nocase ascii wide
        $s4 = "Chromium\\User Data" nocase ascii wide
        $s5 = "Nichrome\\User Data" nocase ascii wide
        $s6 = "Google\\Chrome\\User Data" nocase ascii wide
        $s7 = "360Browser\\Browser\\User Data" nocase ascii wide
        $s8 = "Maxthon3\\User Data" nocase ascii wide
        $s9 = "Comodo\\User Data" nocase ascii wide
        $s10 = "CocCoc\\Browser\\User Data" nocase ascii wide
        $s11 = "Vivaldi\\User Data" nocase ascii wide
        $s12 = "Opera Software\\" nocase ascii wide
        $s13 = "Kometa\\User Data" nocase ascii wide
        $s14 = "Comodo\\Dragon\\User Data" nocase ascii wide
        $s15 = "Sputnik\\User Data" nocase ascii wide
        $s16 = "Google (x86)\\Chrome\\User Data" nocase ascii wide
        $s17 = "Orbitum\\User Data" nocase ascii wide
        $s18 = "Yandex\\YandexBrowser\\User Data" nocase ascii wide
        $s19 = "K-Melon\\User Data" nocase ascii wide
        $s20 = "Flock\\Browser" nocase ascii wide
        $s21 = "ChromePlus\\User Data" nocase ascii wide
        $s22 = "UCBrowser\\" nocase ascii wide
        $s23 = "Mozilla\\SeaMonkey" nocase ascii wide
        $s24 = "Apple\\Apple Application Support\\plutil.exe" nocase ascii wide
        $s25 = "Preferences\\keychain.plist" nocase ascii wide
        $s26 = "SRWare Iron" ascii wide
        $s27 = "CoolNovo" ascii wide
        $s28 = "BlackHawk\\Profiles" ascii wide
        $s29 = "CocCoc\\Browser" ascii wide
        $s30 = "Cyberfox\\Profiles" ascii wide
        $s31 = "Epic Privacy Browser\\" ascii wide
        $s32 = "K-Meleon\\" ascii wide
        $s33 = "Maxthon5\\Users" ascii wide
        $s34 = "Nichrome\\User Data" ascii wide
        $s35 = "Pale Moon\\Profiles" ascii wide
        $s36 = "Waterfox\\Profiles" ascii wide
        $s37 = "Amigo\\User Data" ascii wide
        $s38 = "CentBrowser\\User Data" ascii wide
        $s39 = "Chedot\\User Data" ascii wide
        $s40 = "RockMelt\\User Data" ascii wide
        $s41 = "Go!\\User Data" ascii wide
        $s42 = "7Star\\User Data" ascii wide
        $s43 = "QIP Surf\\User Data" ascii wide
        $s44 = "Elements Browser\\User Data" ascii wide
        $s45 = "TorBro\\Profile" ascii wide
        $s46 = "Suhba\\User Data" ascii wide
        $s47 = "Secure Browser\\User Data" ascii wide
        $s48 = "Mustang\\User Data" ascii wide
        $s49 = "Superbird\\User Data" ascii wide
        $s50 = "Xpom\\User Data" ascii wide
        $s51 = "Bromium\\User Data" ascii wide
        $s52 = "Brave\\" nocase ascii wide
        $s53 = "Google\\Chrome SxS\\User Data" ascii wide
        $s54 = "Microsoft\\Internet Explorer" ascii wide
        $s55 = "Packages\\Microsoft.MicrosoftEdge_" ascii wide
        $s56 = "IceDragon\\Profiles" ascii wide
        $s57 = "\\AdLibs\\" nocase ascii wide
        $s58 = "Moonchild Production\\Pale Moon" nocase ascii wide
        $s59 = "Firefox\\Profiles" nocase ascii wide
        $s60 = "AVG\\Browser\\User Data" nocase ascii wide
        $s61 = "Kinza\\User Data" nocase ascii wide
        $s62 = "URBrowser\\User Data" nocase ascii wide
        $s63 = "AVAST Software\\Browser\\User Data" nocase ascii wide
        $s64 = "SalamWeb\\User Data" nocase ascii wide
        $s65 = "Slimjet\\User Data" nocase ascii wide
        $s66 = "Iridium\\User Data" nocase ascii wide
        $s67 = "Blisk\\User Data" nocase ascii wide
        $s68 = "uCozMedia\\Uran\\User Data" nocase ascii wide
        $s69 = "setting\\modules\\ChromiumViewer" nocase ascii wide
        $s70 = "Citrio\\User Data" nocase ascii wide
        $s71 = "Coowon\\User Data" nocase ascii wide
        $s72 = "liebao\\User Data" nocase ascii wide
        $s73 = "Edge\\User Data" nocase ascii wide
        $s74 = "BlackHawk\\User Data" nocase ascii wide
        $s75 = "QQBrowser\\User Data" nocase ascii wide
        $s76 = "GhostBrowser\\User Data" nocase ascii wide
        $s77 = "Xvast\\User Data" nocase ascii wide
        $s78 = "360Chrome\\Chrome\\User Data" nocase ascii wide
        $s79 = "Brave-Browser\\User Data" nocase ascii wide
        $s80 = "Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer" nocase ascii wide
        $s81 = "Chromodo\\User Data" nocase ascii wide
        $s82 = "Mail.Ru\\Atom\\User Data" nocase ascii wide
        $s83 = "8pecxstudios\\Cyberfox" nocase ascii wide
        $s84 = "NETGATE Technologies\\BlackHaw" nocase ascii wide
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0xfacf) and 6 of them
}

rule INDICATOR_SUSPICIOUS_EXE_References_Confidential_Data_Store {
    meta:
        description = "Detects executables referencing many confidential data stores found in browsers, mail clients, cryptocurreny wallets, etc. Observed in information stealers"
        author = "ditekSHen"
    strings:
        $s1 = "key3.db" nocase ascii wide     // Firefox private keys
        $s2 = "key4.db" nocase ascii wide     // Firefox private keys
        $s3 = "cert8.db" nocase ascii wide    // Firefox certificate database
        $s4 = "logins.json" nocase ascii wide // Firefox encrypted password database
        $s5 = "account.cfn" nocase ascii wide // The Bat! (email client) account credentials
        $s6 = "wand.dat" nocase ascii wide    // Opera password database 
        $s7 = "wallet.dat" nocase ascii wide  // cryptocurreny wallets
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_EXE_References_Messaging_Clients {
    meta:
        description = "Detects executables referencing many email and collaboration clients. Observed in information stealers"
        author = "ditekSHen"
    strings:
        $s1 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook" fullword ascii wide
        $s2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword ascii wide
        $s3 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles" fullword ascii wide
        $s4 = "HKEY_CURRENT_USER\\Software\\Aerofox\\FoxmailPreview" ascii wide
        $s5 = "HKEY_CURRENT_USER\\Software\\Aerofox\\Foxmail" ascii wide
        $s6 = "VirtualStore\\Program Files\\Foxmail\\mail" ascii wide
        $s7 = "VirtualStore\\Program Files (x86)\\Foxmail\\mail" ascii wide
        $s8 = "Opera Mail\\Opera Mail\\wand.dat" ascii wide
        $s9 = "Software\\IncrediMail\\Identities" ascii wide
        $s10 = "Pocomail\\accounts.ini" ascii wide
        $s11 = "Software\\Qualcomm\\Eudora\\CommandLine" ascii wide
        $s12 = "Mozilla Thunderbird\\nss3.dll" ascii wide
        $s13 = "SeaMonkey\\nss3.dll" ascii wide
        $s14 = "Flock\\nss3.dll" ascii wide
        $s15 = "Postbox\\nss3.dll" ascii wide
        $s16 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook" ascii wide
        $s17 = "CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" ascii wide
        $s18 = "Software\\Microsoft\\Office\\Outlook\\OMI Account Manager\\Accounts" ascii wide
        $s19 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii wide
        $s20 = "Files\\Telegram" ascii wide
        $s21 = "Telegram Desktop\\tdata" ascii wide
        $s22 = "Files\\Discord" ascii wide
        $s23 = "Steam\\config" ascii wide
        $s24 = ".purple\\accounts.xml" ascii wide // pidgin
        $s25 = "Skype\\" ascii wide
        $s26 = "Pigdin\\accounts.xml" ascii wide
        $s27 = "Psi\\accounts.xml" ascii wide
        $s28 = "Psi+\\accounts.xml" ascii wide
        $s29 = "Psi\\profiles" ascii wide
        $s30 = "Psi+\\profiles" ascii wide
        $s31 = "Microsoft\\Windows Mail\\account{" ascii wide
        $s32 = "}.oeaccount" ascii wide
        $s33 = "Trillian\\users" ascii wide
        $s34 = "Google Talk\\Accounts" nocase ascii wide
        $s35 = "Microsoft\\Windows Live Mail"  nocase ascii wide
        $s36 = "Google\\Google Talk" nocase ascii wide
        $s37 = "Yahoo\\Pager" nocase ascii wide
        $s38 = "BatMail\\" nocase ascii wide
        $s39 = "POP Peeper\\poppeeper.ini" nocase ascii wide
        $s40 = "Netease\\MailMaster\\data" nocase ascii wide
        $s41 = "Software\\Microsoft\\Office\\17.0\\Outlook\\Profiles\\Outlook" ascii wide
        $s42 = "Software\\Microsoft\\Office\\18.0\\Outlook\\Profiles\\Outlook" ascii wide
        $s43 = "Software\\Microsoft\\Office\\19.0\\Outlook\\Profiles\\Outlook" ascii wide
        $s45 = "Paltalk NG\\common_settings\\core\\users\\creds" ascii wide
        $s46 = "Discord\\Local Storage\\leveldb" ascii wide
        $s47 = "Discord PTB\\Local Storage\\leveldb" ascii wide
        $s48 = "Discord Canary\\leveldb" ascii wide
        $s49 = "MailSpring\\" ascii wide
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients {
    meta:
        description = "Detects executables referencing many file transfer clients. Observed in information stealers"
        author = "ditekSHen"
    strings:
        $s1 = "FileZilla\\recentservers.xml" ascii wide
        $s2 = "Ipswitch\\WS_FTP\\" ascii wide
        $s3 = "SOFTWARE\\\\Martin Prikryl\\\\WinSCP 2\\\\Sessions" ascii wide
        $s4 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" ascii wide
        $s5 = "CoreFTP\\sites" ascii wide
        $s6 = "FTPWare\\COREFTP\\Sites" ascii wide
        $s7 = "HKEY_CURRENT_USERSoftwareFTPWareCOREFTPSites" ascii wide
        $s8 = "FTP Navigator\\Ftplist.txt" ascii wide
        $s9 = "FlashFXP\\3quick.dat" ascii wide
        $s10 = "SmartFTP\\" ascii wide
        $s11 = "cftp\\Ftplist.txt" ascii wide
        $s12 = "Software\\DownloadManager\\Passwords\\" ascii wide
        $s13 = "jDownloader\\config\\database.script" ascii wide
        $s14 = "FileZilla\\sitemanager.xml" ascii wide
        $s15 = "Far Manager\\Profile\\PluginsData\\" ascii wide
        $s16 = "FTPGetter\\Profile\\servers.xml" ascii wide
        $s17 = "FTPGetter\\servers.xml" ascii wide
        $s18 = "Estsoft\\ALFTP\\" ascii wide
        $s19 = "Far\\Plugins\\FTP\\" ascii wide
        $s20 = "Far2\\Plugins\\FTP\\" ascii wide
        $s21 = "Ghisler\\Total Commander" ascii wide
        $s22 = "LinasFTP\\Site Manager" ascii wide
        $s23 = "CuteFTP\\sm.dat" ascii wide
        $s24 = "FlashFXP\\4\\Sites.dat" ascii wide
        $s25 = "FlashFXP\\3\\Sites.dat" ascii wide
        $s26 = "VanDyke\\Config\\Sessions\\" ascii wide
        $s27 = "FTP Explorer\\" ascii wide
        $s28 = "TurboFTP\\" ascii wide
        $s29 = "FTPRush\\" ascii wide
        $s30 = "LeapWare\\LeapFTP\\" ascii wide
        $s31 = "FTPGetter\\" ascii wide
        $s32 = "Far\\SavedDialogHistory\\" ascii wide
        $s33 = "Far2\\SavedDialogHistory\\" ascii wide
        $s34 = "GlobalSCAPE\\CuteFTP " ascii wide
        $s35 = "Ghisler\\Windows Commander" ascii wide
        $s36 = "BPFTP\\Bullet Proof FTP\\" ascii wide
        $s37 = "Sota\\FFFTP" ascii wide
        $s38 = "FTPClient\\Sites" ascii wide
        $s39 = "SOFTWARE\\Robo-FTP 3.7\\" ascii wide
        $s40 = "MAS-Soft\\FTPInfo\\" ascii wide
        $s41 = "SoftX.org\\FTPClient\\Sites" ascii wide
        $s42 = "BulletProof Software\\BulletProof FTP Client\\" ascii wide
        $s43 = "BitKinex\\bitkinex.ds" ascii wide
        $s44 = "Frigate3\\FtpSite.XML" ascii wide
        $s45 = "Directory Opus\\ConfigFiles" ascii wide
        $s56 = "SoftX.org\\FTPClient\\Sites" ascii wide
        $s57 = "South River Technologies\\WebDrive\\Connections" ascii wide
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule INDICATOR_SUSPICIOUS_EXE_References_CryptoWallets {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many cryptocurrency mining wallets or apps. Observed in information stealers"
    strings:
        $app1 = "Ethereum" nocase ascii wide
        $app2 = "Bitcoin" nocase ascii wide
        $app3 = "Litecoin" nocase ascii wide
        $app4 = "NavCoin4" nocase ascii wide
        $app5 = "ByteCoin" nocase ascii wide
        $app6 = "PotCoin" nocase ascii wide
        $app7 = "Gridcoin" nocase ascii wide
        $app8 = "VERGE" nocase ascii wide
        $app9 = "DogeCoin" nocase ascii wide
        $app10 = "FlashCoin" nocase ascii wide
        $app11 = "Sia" nocase ascii wide
        $app12 = "Reddcoin" nocase ascii wide
        $app13 = "Electrum" nocase ascii wide
        $app14 = "Emercoin" nocase ascii wide
        $app15 = "Exodus" nocase ascii wide
        $app16 = "BBQCoin" nocase ascii wide
        $app17 = "Franko" nocase ascii wide
        $app18 = "IOCoin" nocase ascii wide
        $app19 = "Ixcoin" nocase ascii wide
        $app20 = "Mincoin" nocase ascii wide
        $app21 = "YACoin" nocase ascii wide
        $app22 = "Zcash" nocase ascii wide
        $app23 = "devcoin" nocase ascii wide
        $app24 = "Dash" nocase ascii wide
        $app25 = "Monero" nocase ascii wide
        $app26 = "Riot Games\\" nocase ascii wide
        $app27 = "qBittorrent\\" nocase ascii wide
        $app28 = "Battle.net\\" nocase ascii wide
        $app29 = "Steam\\" nocase ascii wide
        $app30 = "Valve\\Steam\\" nocase ascii wide
        $app31 = "Anoncoin" nocase ascii wide
        $app32 = "DashCore" nocase ascii wide
        $app33 = "DevCoin" nocase ascii wide
        $app34 = "DigitalCoin" nocase ascii wide
        $app35 = "Electron" nocase ascii wide
        $app36 = "ElectrumLTC" nocase ascii wide
        $app37 = "FlorinCoin" nocase ascii wide
        $app38 = "FrancoCoin" nocase ascii wide
        $app39 = "JAXX" nocase ascii wide
        $app40 = "MultiDoge" ascii wide
        $app41 = "TerraCoin" ascii wide
        $app42 = "Electrum-LTC" ascii wide
        $app43 = "ElectrumG" ascii wide
        $app44 = "Electrum-btcp" ascii wide
        $app45 = "MultiBitHD" ascii wide
        $app46 = "monero-project" ascii wide
        $app47 = "Bitcoin-Qt" ascii wide
        $app48 = "BitcoinGold-Qt" ascii wide
        $app49 = "Litecoin-Qt" ascii wide
        $app50 = "BitcoinABC-Qt" ascii wide
        $app51 = "Exodus Eden" ascii wide
        $app52 = "myether" ascii wide
        $app53 = "factores-Binance" ascii wide
        $app54 = "metamask" ascii wide
        $app55 = "kucoin" ascii wide
        $app56 = "cryptopia" ascii wide
        $app57 = "binance" ascii wide
        $app58 = "hitbtc" ascii wide
        $app59 = "litebit" ascii wide
        $app60 = "coinEx" ascii wide
        $app61 = "blockchain" ascii wide
        $app62 = "\\Armory" ascii wide
        $app63 = "\\Atomic" ascii wide
        $app64 = "\\Bytecoin" ascii wide
        $app65 = "simpleos" ascii wide
        $app66 = "WalletWasabi" ascii wide
        $app67 = "atomic\\" ascii wide
        $app68 = "Guarda\\" ascii wide
        $app69 = "Neon\\" ascii wide
        $app70 = "Blockstream\\" ascii wide
        $app71 = "GreenAddress Wallet\\" ascii wide
        $app72 = "bitpay\\" ascii wide

        $ne1 = "C:\\src\\pgriffais_incubator-w7\\Steam\\main\\src\\external\\libjingle-0.4.0\\talk/base/scoped_ptr.h" fullword wide
        $ne2 = "\"%s\\bin\\%slauncher.exe\" -hproc %x -hthread %x -baseoverlayname %s\\%s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (not any of ($ne*) and 6 of them)
}

rule INDICATOR_SUSPICIOUS_ClearWinLogs {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing commands for clearing Windows Event Logs"
    strings:
        $cmd1 = "wevtutil.exe clear-log" ascii wide nocase
        $cmd2 = "wevtutil.exe cl " ascii wide nocase
        $cmd3 = ".ClearEventLog()" ascii wide nocase
        $cmd4 = "Foreach-Object {wevtutil cl \"$_\"}" ascii wide nocase
        $cmd5 = "('wevtutil.exe el') DO (call :do_clear" ascii wide nocase
        $cmd6 = "| ForEach { Clear-EventLog $_.Log }" ascii wide nocase
        $cmd7 = "('wevtutil.exe el') DO wevtutil.exe cl \"%s\"" ascii wide nocase
        $cmd8 = "Clear-EventLog -LogName application, system, security" ascii wide nocase
        $t1 = "wevtutil" ascii wide nocase
        $l1 = "cl Application" ascii wide nocase
        $l2 = "cl System" ascii wide nocase
        $l3 = "cl Setup" ascii wide nocase
        $l4 = "cl Security" ascii wide nocase
        $l5 = "sl Security /e:false" ascii wide nocase
        $ne1 = "wevtutil.exe cl Aplicaci" fullword wide
        $ne2 = "wevtutil.exe cl Application /bu:C:\\admin\\backup\\al0306.evtx" fullword wide
        $ne3 = "wevtutil.exe cl Application /bu:C:\\admin\\backups\\al0306.evtx" fullword wide
    condition:
        uint16(0) == 0x5a4d and not any of ($ne*) and ((1 of ($cmd*)) or (1 of ($t*) and 3 of ($l*)))
}

rule INDICATOR_SUSPICIOUS_DisableWinDefender {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing artifcats associated with disabling Widnows Defender"
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii wide nocase
        $reg2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
        $s1 = "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true" ascii wide nocase
        $s2 = "Set-MpPreference -DisableArchiveScanning $true" ascii wide nocase
        $s3 = "Set-MpPreference -DisableIntrusionPreventionSystem $true" ascii wide nocase
        $s4 = "Set-MpPreference -DisableScriptScanning $true" ascii wide nocase
        $s5 = "Set-MpPreference -SubmitSamplesConsent 2" ascii wide nocase
        $s6 = "Set-MpPreference -MAPSReporting 0" ascii wide nocase
        $s7 = "Set-MpPreference -HighThreatDefaultAction 6" ascii wide nocase
        $s8 = "Set-MpPreference -ModerateThreatDefaultAction 6" ascii wide nocase
        $s9 = "Set-MpPreference -LowThreatDefaultAction 6" ascii wide nocase
        $s10 = "Set-MpPreference -SevereThreatDefaultAction 6" ascii wide nocase
        $s11 = "Set-MpPreference -EnableControlledFolderAccess Disabled" ascii wide nocase
        $pdb = "\\Disable-Windows-Defender\\obj\\Debug\\Disable-Windows-Defender.pdb" ascii
        $e1 = "Microsoft\\Windows Defender\\Exclusions\\Paths" ascii wide nocase
        $e2 = "Add-MpPreference -Exclusion" ascii wide nocase
        $c1 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($reg*) and 1 of ($s*)) or ($pdb) or all of ($e*) or #c1 > 1)
}

rule INDICATOR_SUSPICIOUS_USNDeleteJournal {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing anti-forensic artifcats of deletiing USN change journal. Observed in ransomware"
    strings:
        $cmd1 = "fsutil.exe" ascii wide nocase
        $s1 = "usn deletejournal /D C:" ascii wide nocase
        $s2 = "fsutil.exe usn deletejournal" ascii wide nocase
        $s3 = "fsutil usn deletejournal" ascii wide nocase
        $s4 = "fsutil file setZeroData offset=0" ascii wide nocase
        $ne1 = "fsutil usn readdata C:\\Temp\\sample.txt" wide
        $ne2 = "fsutil transaction query {0f2d8905-6153-449a-8e03-7d3a38187ba1}" wide
        $ne3 = "fsutil resource start d:\\foobar d:\\foobar\\LogDir\\LogBLF::TxfLog d:\\foobar\\LogDir\\LogBLF::TmLog" wide
        $ne4 = "fsutil objectid query C:\\Temp\\sample.txt" wide
    condition:
        uint16(0) == 0x5a4d and (not any of ($ne*) and ((1 of ($cmd*) and 1 of ($s*)) or 1 of ($s*)))
}

rule INDICATOR_SUSPICIOUS_GENInfoStealer {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing common artifcats observed in infostealers"
    strings:
        $f1 = "FileZilla\\recentservers.xml" ascii wide
        $f2 = "FileZilla\\sitemanager.xml" ascii wide
        $f3 = "SOFTWARE\\\\Martin Prikryl\\\\WinSCP 2\\\\Sessions" ascii wide
        $b1 = "Chrome\\User Data\\" ascii wide
        $b2 = "Mozilla\\Firefox\\Profiles" ascii wide
        $b3 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" ascii wide
        $b4 = "Opera Software\\Opera Stable\\Login Data" ascii wide
        $b5 = "YandexBrowser\\User Data\\" ascii wide
        $s1 = "key3.db" nocase ascii wide
        $s2 = "key4.db" nocase ascii wide
        $s3 = "cert8.db" nocase ascii wide
        $s4 = "logins.json" nocase ascii wide
        $s5 = "account.cfn" nocase ascii wide
        $s6 = "wand.dat" nocase ascii wide
        $s7 = "wallet.dat" nocase ascii wide
        $a1 = "username_value" ascii wide
        $a2 = "password_value" ascii wide
        $a3 = "encryptedUsername" ascii wide
        $a4 = "encryptedPassword" ascii wide
        $a5 = "httpRealm" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((2 of ($f*) and 2 of ($b*) and 1 of ($s*) and 3 of ($a*)) or (14 of them))
}

rule INDICATOR_SUSPICIOUS_NTLM_Exfiltration_IPPattern {
    meta:
        author = "ditekSHen"
        description = "Detects NTLM hashes exfiltration patterns in command line and various file types"
    strings:
        // Example (CMD): net use \\1.2.3.4@80\t
        $s1 = /net\suse\s\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (PDF): /F (\\\\IP@80\\t)
        $s2 = /\/F\s\(\\\\\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (LNK): URL=file://IP@80/t.htm
        $s3 = /URL=file:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (ICO): IconFile=\\IP@80\t.ico
        $s4 = /IconFile=\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (DOC, DOCX): Target="file://IP@80/t.dotx"
        $s5 = /Target=\x22:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (Subdoc ??): ///IP@80/t
        $s6 = /\/\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (over SSL) - DavWWWRoot keyword actually triggers WebDAV forcibly
        $s7 = /\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@SSL@\d+\\DavWWWRoot/ ascii wide

        // OOXML in addtion to PK magic
        $mso1 = "word/" ascii
        $mso2 = "ppt/" ascii
        $mso3 = "xl/" ascii
        $mso4 = "[Content_Types].xml" ascii
    condition:
        ((uint32(0) == 0x46445025 or (uint16(0) == 0x004c and uint32(4) == 0x00021401) or uint32(0) == 0x00010000 or (uint16(0) == 0x4b50 and 1 of ($mso*))) and 1 of ($s*)) or 1 of ($s*)
}

rule INDICATOR_SUSPICIOUS_PWSH_B64Encoded_Concatenated_FileEXEC {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell scripts containing patterns of base64 encoded files, concatenation and execution"
    strings:
        $b1 = "::WriteAllBytes(" ascii
        $b2 = "::FromBase64String(" ascii
        $b3 = "::UTF8.GetString(" ascii

        $s1 = "-join" nocase ascii
        $s2 = "[Char]$_"
        $s3 = "reverse" nocase ascii
        $s4 = " += " ascii

        $e1 = "System.Diagnostics.Process" ascii
        $e2 = /StartInfo\.(Filename|UseShellExecute)/ ascii
        $e3 = /-eq\s'\.(exe|dll)'\)/ ascii
        $e4 = /(Get|Start)-(Process|WmiObject)/ ascii
    condition:
        #s4 > 10 and ((3 of ($b*)) or (1 of ($b*) and 2 of ($s*) and 1 of ($e*)) or (8 of them))
}

rule INDICATOR_SUSPICIOUS_PWSH_AsciiEncoding_Pattern {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell scripts containing ASCII encoded files"
    strings:
        $enc1 = "[char[]]([char]97..[char]122)" ascii
        $enc2 = "[char[]]([char]65..[char]90)" ascii
        $s1 = ".DownloadData($" ascii
        $s2 = "[Net.SecurityProtocolType]::TLS12" ascii
        $s3 = "::WriteAllBytes($" ascii
        $s4 = "::FromBase64String($" ascii
        $s5 = "Get-Random" ascii
    condition:
        1 of ($enc*) and 4 of ($s*) and filesize < 2500KB
}

rule INDICATOR_SUSPICIOUS_JS_Hex_B64Encoded_EXE {
    meta:
        author = "ditekSHen"
        description = "Detects JavaScript files hex and base64 encoded executables"
    strings:
        $s1 = ".SaveToFile" ascii
        $s2 = ".Run" ascii
        $s3 = "ActiveXObject" ascii
        $s4 = "fromCharCode" ascii
        $s5 = "\\x66\\x72\\x6F\\x6D\\x43\\x68\\x61\\x72\\x43\\x6F\\x64\\x65" ascii
        $binary = "\\x54\\x56\\x71\\x51\\x41\\x41" ascii
        $pattern = /[\s\{\(\[=]_0x[0-9a-z]{3,6}/ ascii
    condition:
        $binary and $pattern and 2 of ($s*) and filesize < 2500KB
}

rule INDICATOR_SUSPICIOUS_JS_LocalPersistence {
    meta:
        author = "ditekSHen"
        description = "Detects JavaScript files used for persistence and executable or script execution"
    strings:
        $s1 = "ActiveXObject" ascii
        $s2 = "Shell.Application" ascii
        $s3 = "ShellExecute" ascii

        $ext1 = ".exe" ascii
        $ext2 = ".ps1" ascii
        $ext3 = ".lnk" ascii
        $ext4 = ".hta" ascii
        $ext5 = ".dll" ascii
        $ext6 = ".vb" ascii
        $ext7 = ".com" ascii
        $ext8 = ".js" ascii

        $action = "\"Open\"" ascii
    condition:
       $action and 2 of ($s*) and 1 of ($ext*) and filesize < 500KB
}

rule INDICATOR_SUSPICIOUS_WMIC_Downloader {
    meta:
        author = "ditekSHen"
        description = "Detects files utilizing WMIC for whitelisting bypass and downloading second stage payloads"
    strings:
        $s1 = "WMIC.exe os get /format:\"http" wide
        $s2 = "WMIC.exe computersystem get /format:\"http" wide
        $s3 = "WMIC.exe dcomapp get /format:\"http" wide
        $s4 = "WMIC.exe desktop get /format:\"http" wide
    condition:
        (uint16(0) == 0x004c or uint16(0) == 0x5a4d) and 1 of them
}

rule INDICATOR_SUSPICIOUS_AMSI_Bypass {
    meta:
        author = "ditekSHen"
        description = "Detects AMSI bypass pattern"
    strings:
        $v1_1 = "[Ref].Assembly.GetType(" ascii nocase
        $v1_2 = "System.Management.Automation.AmsiUtils" ascii
        $v1_3 = "GetField(" ascii nocase
        $v1_4 = "amsiInitFailed" ascii
        $v1_5 = "NonPublic,Static" ascii
        $v1_6 = "SetValue(" ascii nocase
    condition:
        5 of them and filesize < 2000KB
}

rule INDICATOR_SUSPICIOUS_EXE_PE_ResourceTuner {
    meta:
        author = "ditekSHen"
        description = "Detects executables with modified PE resources using the unpaid version of Resource Tuner"
    strings:
        $s1 = "Modified by an unpaid evaluation copy of Resource Tuner 2 (www.heaventools.com)" fullword wide
    condition:
        uint16(0) == 0x5a4d and all of them 
}

rule INDICATOR_SUSPICIOUS_EXE_ASEP_REG_Reverse {
    meta:
        author = "ditekSHen"
        description = "Detects file containing reversed ASEP Autorun registry keys"
    strings:
        $s1 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s2 = "ecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s3 = "secivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s4 = "xEecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s5 = "ecnOsecivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s6 = "yfitoN\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s7 = "tiniresU\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s8 = "nuR\\rerolpxE\\seiciloP\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s9 = "stnenopmoC dellatsnI\\puteS evitcA\\tfosorciM" ascii wide nocase
        $s10 = "sLLD_tinIppA\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s11 = "snoitpO noitucexE eliF egamI\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s12 = "llehS\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s13 = "daol\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s14 = "daoLyaleDtcejbOecivreSllehS\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s15 = "nuRotuA\\rossecorP\\dnammoC\\tfosorciM" ascii wide nocase
        $s16 = "putratS\\sredloF llehS resU\\rerolpxE\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s17 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\teSlortnoCtnerruC\\metsyS" ascii wide nocase
        $s18 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\100teSlortnoC\\metsyS" ascii wide nocase
        $s19 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\erawtfoS" ascii wide nocase
        $s20 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\edoN2346woW\\erawtfoS" ascii wide nocase
    condition:
        1 of them and filesize < 2000KB
}

rule INDICATOR_SUSPICIOUS_EXE_SQLQuery_ConfidentialDataStore {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing SQL queries to confidential data stores. Observed in infostealers"
    strings:
        $select = "select " ascii wide nocase
        $table1 = " from credit_cards" ascii wide nocase
        $table2 = " from logins" ascii wide nocase
        $table3 = " from cookies" ascii wide nocase
        $table4 = " from moz_cookies" ascii wide nocase
        $table5 = " from moz_formhistory" ascii wide nocase
        $table6 = " from moz_logins" ascii wide nocase
        $column1 = "name" ascii wide nocase
        $column2 = "password_value" ascii wide nocase
        $column3 = "encrypted_value" ascii wide nocase
        $column4 = "card_number_encrypted" ascii wide nocase
        $column5 = "isHttpOnly" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 2 of ($table*) and 2 of ($column*) and $select
}

rule INDICATOR_SUSPICIOUS_References_SecTools {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many IR and analysis tools"
    strings:
        $s1 = "procexp.exe" nocase ascii wide
        $s2 = "perfmon.exe" nocase ascii wide
        $s3 = "autoruns.exe" nocase ascii wide
        $s4 = "autorunsc.exe" nocase ascii wide
        $s5 = "ProcessHacker.exe" nocase ascii wide
        $s6 = "procmon.exe" nocase ascii wide
        $s7 = "sysmon.exe" nocase ascii wide
        $s8 = "procdump.exe" nocase ascii wide
        $s9 = "apispy.exe" nocase ascii wide
        $s10 = "dumpcap.exe" nocase ascii wide
        $s11 = "emul.exe" nocase ascii wide
        $s12 = "fortitracer.exe" nocase ascii wide
        $s13 = "hookanaapp.exe" nocase ascii wide
        $s14 = "hookexplorer.exe" nocase ascii wide
        $s15 = "idag.exe" nocase ascii wide
        $s16 = "idaq.exe" nocase ascii wide
        $s17 = "importrec.exe" nocase ascii wide
        $s18 = "imul.exe" nocase ascii wide
        $s19 = "joeboxcontrol.exe" nocase ascii wide
        $s20 = "joeboxserver.exe" nocase ascii wide
        $s21 = "multi_pot.exe" nocase ascii wide
        $s22 = "ollydbg.exe" nocase ascii wide
        $s23 = "peid.exe" nocase ascii wide
        $s24 = "petools.exe" nocase ascii wide
        $s25 = "proc_analyzer.exe" nocase ascii wide
        $s26 = "regmon.exe" nocase ascii wide
        $s27 = "scktool.exe" nocase ascii wide
        $s28 = "sniff_hit.exe" nocase ascii wide
        $s29 = "sysanalyzer.exe" nocase ascii wide
        $s30 = "CaptureProcessMonitor.sys" nocase ascii wide
        $s31 = "CaptureRegistryMonitor.sys" nocase ascii wide
        $s32 = "CaptureFileMonitor.sys" nocase ascii wide
        $s33 = "Control.exe" nocase ascii wide
        $s34 = "rshell.exe" nocase ascii wide
        $s35 = "smc.exe" nocase ascii wide
    condition:
         uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_SUSPICIOUS_References_SecTools_B64Encoded {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many base64-encoded IR and analysis tools names"
    strings:
        $s1 = "VGFza21ncg==" ascii wide  // Taskmgr
        $s2 = "dGFza21ncg==" ascii wide  // taskmgr
        $s3 = "UHJvY2Vzc0hhY2tlcg" ascii wide // ProcessHacker
        $s4 = "cHJvY2V4cA" ascii wide  // procexp
        $s5 = "cHJvY2V4cDY0" ascii wide  // procexp64
        $s6 = "aHR0cCBhbmFseXplci" ascii wide // http analyzer
        $s7 = "ZmlkZGxlcg" ascii wide // fiddler
        $s8 = "ZWZmZXRlY2ggaHR0cCBzbmlmZmVy" ascii wide // effetech http sniffer
        $s9 = "ZmlyZXNoZWVw" ascii wide // firesheep
        $s10 = "SUVXYXRjaCBQcm9mZXNzaW9uYWw" ascii wide // IEWatch Professional
        $s11 = "ZHVtcGNhcA" ascii wide // dumpcap
        $s12 = "d2lyZXNoYXJr" ascii wide //wireshark
        $s13 = "c3lzaW50ZXJuYWxzIHRjcHZpZXc" ascii wide // sysinternals tcpview
        $s14 = "TmV0d29ya01pbmVy" ascii wide // NetworkMiner
        $s15 = "TmV0d29ya1RyYWZmaWNWaWV3" ascii wide // NetworkTrafficView
        $s16 = "SFRUUE5ldHdvcmtTbmlmZmVy" ascii wide // HTTPNetworkSniffer
        $s17 = "dGNwZHVtcA" ascii wide // tcpdump
        $s18 = "aW50ZXJjZXB0ZXI" ascii wide // intercepter
        $s19 = "SW50ZXJjZXB0ZXItTkc" ascii wide // Intercepter-NG
        $s20 = "b2xseWRiZw" ascii wide // ollydbg
        $s21 = "eDY0ZGJn" ascii wide // x64dbg
        $s22 = "eDMyZGJn" ascii wide // x32dbg
        $s23 = "ZG5zcHk" ascii wide // dnspy
        $s24 = "ZGU0ZG90" ascii wide // de4dot
        $s25 = "aWxzcHk" ascii wide // ilspy
        $s26 = "ZG90cGVla" ascii wide // dotpeek
        $s27 = "aWRhNjQ" ascii wide // ida64
        $s28 = "UkRHIFBhY2tlciBEZXRlY3Rvcg" ascii wide // RDG Packer Detector
        $s29 = "Q0ZGIEV4cGxvcmVy" ascii wide // CFF Explorer
        $s30 = "UEVpRA" ascii wide // PEiD
        $s31 = "cHJvdGVjdGlvbl9pZA" ascii wide // protection_id
        $s32 = "TG9yZFBF" ascii wide // LordPE
        $s33 = "cGUtc2lldmU=" ascii wide // pe-sieve
        $s34 = "TWVnYUR1bXBlcg" ascii wide // MegaDumper
        $s35 = "VW5Db25mdXNlckV4" ascii wide // UnConfuserEx
        $s36 = "VW5pdmVyc2FsX0ZpeGVy" ascii wide // Universal_Fixer
        $s37 = "Tm9GdXNlckV4" ascii wide // NoFuserEx
    condition:
         uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_SUSPICIOUS_References_Sandbox_Artifacts {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing sandbox artifacts"
    strings:
        $s1 = "C:\\agent\\agent.pyw" ascii wide
        $s2 = "C:\\sandbox\\starter.exe" ascii wide
        $s3 = "c:\\ipf\\BDCore_U.dll" ascii wide
        $s4 = "C:\\cwsandbox_manager" ascii wide
        $s5 = "C:\\cwsandbox" ascii wide
        $s6 = "C:\\Stuff\\odbg110" ascii wide
        $s7 = "C:\\gfisandbox" ascii wide
        $s8 = "C:\\Virus Analysis" ascii wide
        $s9 = "C:\\iDEFENSE\\SysAnalyzer" ascii wide
        $s10 = "c:\\gnu\\bin" ascii wide
        $s11 = "C:\\SandCastle\\tools" ascii wide
        $s12 = "C:\\cuckoo\\dll" ascii wide
        $s13 = "C:\\MDS\\WinDump.exe" ascii wide
        $s14 = "C:\\tsl\\Raptorclient.exe" ascii wide
        $s15 = "C:\\guest_tools\\start.bat" ascii wide
        $s16 = "C:\\tools\\aswsnx\\snxcmd.exe" ascii wide
        $s17 = "C:\\Winap\\ckmon.pyw" ascii wide
        $s18 = "c:\\tools\\decodezeus" ascii wide
        $s19 = "c:\\tools\\aswsnx" ascii wide
        $s20 = "C:\\sandbox\\starter.exe" ascii wide
        $s21 = "C:\\Kit\\procexp.exe" ascii wide
        $s22 = "c:\\tracer\\mdare32_0.sys" ascii wide
        $s23 = "C:\\tool\\malmon" ascii wide
        $s24 = "C:\\Samples\\102114\\Completed" ascii wide
        $s25 = "c:\\vmremote\\VmRemoteGuest.exe" ascii wide
        $s26 = "d:\\sandbox_svc.exe" ascii wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_EXE_Embedded_Gzip_B64Encoded_File {
     meta:
        author = "ditekSHen"
        description = "Detects executables containing bas64 encoded gzip files"
    strings:
        $s1 = "H4sIAAAAAAA" ascii wide
        $s2 = "AAAAAAAIs4H" ascii wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_SUSPICIOUS_EXE_RawGitHub_URL {
     meta:
        author = "ditekSHen"
        description = "Detects executables containing URLs to raw contents of a Github gist"
    strings:
        $url1 = "https://gist.githubusercontent.com/" ascii wide
        $url2 = "https://raw.githubusercontent.com/" ascii wide
        $raw = "/raw/" ascii wide
    condition:
        uint16(0) == 0x5a4d and (($url1 and $raw) or ($url2))
}

rule INDICATOR_SUSPICIOUS_EXE_RawPaste_URL {
     meta:
        author = "ditekSHen"
        description = "Detects executables (downlaoders) containing URLs to raw contents of a paste"
    strings:
        $u1 = "https://pastebin.com/" ascii wide nocase
        $u2 = "https://paste.ee/" ascii wide nocase
        $u3 = "https://pastecode.xyz/" ascii wide nocase
        $u4 = "https://rentry.co/" ascii wide nocase
        $u5 = "https://paste.nrecom.net/" ascii wide nocase
        $u6 = "https://hastebin.com/" ascii wide nocase
        $u7 = "https://privatebin.info/" ascii wide nocase
        $u8 = "https://penyacom.org/" ascii wide nocase
        $u9 = "https://controlc.com/" ascii wide nocase
        $u10 = "https://tiny-paste.com/" ascii wide nocase
        $u11 = "https://paste.teknik.io/" ascii wide nocase
        $u12 = "https://privnote.com/" ascii wide nocase
        $u13 = "https://hushnote.herokuapp.com/" ascii wide nocase
        $s1 = "/raw/" ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($u*) and all of ($s*))
}

rule INDICATOR_SUSPICIOUS_EXE_RawPaste_Reverse_URL {
     meta:
        author = "ditekSHen"
        description = "Detects executables (downloaders) containing reversed URLs to raw contents of a paste"
    strings:
        $u1 = "/moc.nibetsap//:sptth" ascii wide nocase
        $u2 = "/ee.etsap//:sptth" ascii wide nocase
        $u3 = "/zyx.edocetsap//:sptth" ascii wide nocase
        $u4 = "/oc.yrtner//:sptth" ascii wide nocase
        $u5 = "/ten.mocern.etsap//:sptth" ascii wide nocase
        $u6 = "/moc.nibetsah//:sptth" ascii wide nocase
        $u7 = "/ofni.nibetavirp//:sptth" ascii wide nocase
        $u8 = "/gro.mocaynep//:sptth" ascii wide nocase
        $u9 = "/moc.clortnoc//:sptth" ascii wide nocase
        $u10 = "/moc.etsap-ynit//:sptth" ascii wide nocase
        $u11 = "/oi.kinket.etsap//:sptth" ascii wide nocase
        $u12 = "/moc.etonvirp//:sptth" ascii wide nocase
        $u13 = "/moc.ppaukoreh.etonhsuh//:sptth" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 1 of ($u*)
}

rule INDICATOR_SUSPICIOUS_PWSH_PasswordCredential_RetrievePassword {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell content designed to retrieve passwords from host"
    strings:
        $namespace = "Windows.Security.Credentials.PasswordVault" ascii wide nocase
        $method1 = "RetrieveAll()" ascii wide nocase
        $method2 = ".RetrievePassword()" ascii wide nocase
    condition:
       $namespace and 1 of ($method*)
}

/*
rule INDICATOR_SUSPICIOUS_Stomped_PECompilation_Timestamp_InTheFuture {
    meta:
        author = "ditekSHen"
        description = "Detect executables with stomped PE compilation timestamp that is greater than local current time"
    condition:
        uint16(0) == 0x5a4d and pe.timestamp > time.now()
}
*/

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_EnvVarScheduledTasks {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC (ab)using Environment Variables in Scheduled Tasks"
    strings:
        $s1 = "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" ascii wide
        $s2 = "\\Environment" ascii wide
        $s3 = "schtasks" ascii wide
        $s4 = "/v windir" ascii wide
    condition:
       all of them
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_fodhelper {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC using fodhelper.exe"
    strings:
        $s1 = "\\software\\classes\\ms-settings\\shell\\open\\command" ascii wide nocase
        $s2 = "DelegateExecute" ascii wide
        $s3 = "fodhelper" ascii wide
        $s4 = "ConsentPromptBehaviorAdmin" ascii wide
    condition:
       all of them
}

/*
rule INDICATOR_SUSPICIOUS_EXE_Contains_MD5_Named_DLL {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC using fodhelper.exe"
    strings:
        $s1 = /[a-f0-9]{32}\.dll/ ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}
*/

rule INDICATOR_SUSPICIOUS_Finger_Download_Pattern {
    meta:
        author = "ditekSHen"
        description = "Detects files embedding and abusing the finger command for download"
    strings:
        $pat1 = /finger(\.exe)?\s.{1,50}@.{7,10}\|/ ascii wide
        $pat2 = "-Command \"finger" ascii wide
        $ne1 = "Nmap service detection probe list" ascii
    condition:
       not any of ($ne*) and any of ($pat*)
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCMD {
    meta:
        author = "ditekSHen"
        description = "Detects Windows exceutables bypassing UAC using CMSTP utility, command line and INF"
    strings:
        $s1 = "c:\\windows\\system32\\cmstp.exe" ascii wide nocase
        $s2 = "taskkill /IM cmstp.exe /F" ascii wide nocase
        $s3 = "CMSTPBypass" fullword ascii
        $s4 = "CommandToExecute" fullword ascii
        $s5 = "RunPreSetupCommands=RunPreSetupCommandsSection" fullword wide
        $s6 = "\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \"%UnexpectedError%\", \"\"" fullword wide nocase
    condition:
       uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_JS_WMI_ExecQuery {
    meta:
        author = "ditekSHen"
        description = "Detects JS potentially executing WMI queries"
    strings:
        $ex = ".ExecQuery(" ascii nocase
        $s1 = "GetObject(" ascii nocase
        $s2 = "String.fromCharCode(" ascii nocase
        $s3 = "ActiveXObject(" ascii nocase
        $s4 = ".Sleep(" ascii nocase
    condition:
       ($ex and all of ($s*))
}

rule INDICATOR_SUSPICIOUS_EXE_SandboxUserNames {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing possible sandbox analysis VM usernames"
    strings:
        $s1 = "15pb" fullword ascii wide nocase
        $s2 = "7man2" fullword ascii wide nocase
        $s3 = "stella" fullword ascii wide nocase
        $s4 = "f4kh9od" fullword ascii wide nocase
        $s5 = "willcarter" fullword ascii wide nocase
        $s6 = "biluta" fullword ascii wide nocase
        $s7 = "ehwalker" fullword ascii wide nocase
        $s8 = "hong lee" fullword ascii wide nocase
        $s9 = "joe cage" fullword ascii wide nocase
        $s10 = "jonathan" fullword ascii wide nocase
        $s11 = "kindsight" fullword ascii wide nocase
        $s12 = "malware" fullword ascii wide nocase
        $s13 = "peter miller" fullword ascii wide nocase
        $s14 = "petermiller" fullword ascii wide nocase
        $s15 = "phil" fullword ascii wide nocase
        $s16 = "rapit" fullword ascii wide nocase
        $s17 = "r0b0t" fullword ascii wide nocase
        $s18 = "cuckoo" fullword ascii wide nocase
        $s19 = "vm-pc" fullword ascii wide nocase
        $s20 = "analyze" fullword ascii wide nocase
        $s21 = "roslyn" fullword ascii wide nocase
        $s22 = "vince" fullword ascii wide nocase
        $s23 = "test" fullword ascii wide nocase
        $s24 = "sample" fullword ascii wide nocase
        $s25 = "mcafee" fullword ascii wide nocase
        $s26 = "vmscan" fullword ascii wide nocase
        $s27 = "mallab" fullword ascii wide nocase
        $s28 = "abby" fullword ascii wide nocase
        $s29 = "elvis" fullword ascii wide nocase
        $s30 = "wilbert" fullword ascii wide nocase
        $s31 = "joe smith" fullword ascii wide nocase
        $s32 = "hanspeter" fullword ascii wide nocase
        $s33 = "johnson" fullword ascii wide nocase
        $s34 = "placehole" fullword ascii wide nocase
        $s35 = "tequila" fullword ascii wide nocase
        $s36 = "paggy sue" fullword ascii wide nocase
        $s37 = "klone" fullword ascii wide nocase
        $s38 = "oliver" fullword ascii wide nocase
        $s39 = "stevens" fullword ascii wide nocase
        $s40 = "ieuser" fullword ascii wide nocase
        $s41 = "virlab" fullword ascii wide nocase
        $s42 = "beginer" fullword ascii wide nocase
        $s43 = "beginner" fullword ascii wide nocase
        $s44 = "markos" fullword ascii wide nocase
        $s45 = "semims" fullword ascii wide nocase
        $s46 = "gregory" fullword ascii wide nocase
        $s47 = "tom-pc" fullword ascii wide nocase
        $s48 = "will carter" fullword ascii wide nocase
        $s49 = "angelica" fullword ascii wide nocase
        $s50 = "eric johns" fullword ascii wide nocase
        $s51 = "john ca" fullword ascii wide nocase
        $s52 = "lebron james" fullword ascii wide nocase
        $s53 = "rats-pc" fullword ascii wide nocase
        $s54 = "robot" fullword ascii wide nocase
        $s55 = "serena" fullword ascii wide nocase
        $s56 = "sofynia" fullword ascii wide nocase
        $s57 = "straz" fullword ascii wide nocase
        $s58 = "bea-ch" fullword ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 10 of them
}

rule INDICATOR_SUSPICIOUS_XML_Liverpool_Downlaoder_UserConfig {
    meta:
        author = "ditekSHen"
        description = "Detects XML files associated with 'Liverpool' downloader containing encoded executables"
    strings:
        $s1 = "<configSections>" ascii nocase
        $s2 = "<value>77 90" ascii nocase
    condition:
       uint32(0) == 0x6d783f3c and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_B64_Encoded_UserAgent {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing base64 encoded User Agent"
    strings:
        $s1 = "TW96aWxsYS81LjAgK" ascii wide
        $s2 = "TW96aWxsYS81LjAgKFdpbmRvd3M" ascii wide
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule INDICATOR_SUSPICIOUS_EXE_WindDefender_AntiEmaulation {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing potential Windows Defender anti-emulation checks"
    strings:
        $s1 = "JohnDoe" fullword ascii wide
        $s2 = "HAL9TH" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_attrib {
    meta:
        author = "ditekSHen"
        description = "Detects executables using attrib with suspicious attributes attributes"
    strings:
        $s1 = "attrib +h +r +s" ascii wide
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule INDICATOR_SUSPICIOUS_EXE_ClearMyTracksByProcess {
    meta:
        author = "ditekSHen"
        description = "Detects executables calling ClearMyTracksByProcess"
    strings:
        $s1 = "InetCpl.cpl,ClearMyTracksByProcess" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule INDICATOR_SUSPICIOUS_EXE_DotNetProcHook {
    meta:
        author = "ditekSHen"
        description = "Detects executables with potential process hoocking"
    strings:
        $s1 = "UnHook" fullword ascii
        $s2 = "SetHook" fullword ascii
        $s3 = "CallNextHook" fullword ascii
        $s4 = "_hook" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_TelegramChatBot {
    meta:
        author = "ditekSHen"
        description = "Detects executables using Telegram Chat Bot"
    strings:
        $s1 = "https://api.telegram.org/bot" ascii wide
        $s2 = "/sendMessage?chat_id=" fullword ascii wide
        $s3 = "Content-Disposition: form-data; name=\"" fullword ascii
        $s4 = "/sendDocument?chat_id=" fullword ascii wide
        $p1 = "/sendMessage" ascii wide
        $p2 = "/sendDocument" ascii wide
        $p3 = "&chat_id=" ascii wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or (2 of ($p*) and 1 of ($s*)))
}

rule INDICATOR_SUSPICIOUS_EXE_B64_Artifacts {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding bas64-encoded APIs, command lines, registry keys, etc."
    strings:
        $s1 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA" ascii wide
        $s2 = "L2Mgc2NodGFza3MgL2" ascii wide
        $s3 = "QW1zaVNjYW5CdWZmZXI" ascii wide
        $s4 = "VmlydHVhbFByb3RlY3Q" ascii wide
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_SUSPICIOUS_EXE_DiscordURL {
    meta:
        author = "ditekSHen"
        description = "Detects executables Discord URL observed in first stage droppers"
    strings:
        $s1 = "https://discord.com/api/webhooks/" ascii wide nocase
        $s2 = "https://cdn.discordapp.com/attachments/" ascii wide nocase
        $s3 = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va" ascii wide
        $s4 = "aHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobW" ascii wide
        $s5 = "/skoohbew/ipa/moc.drocsid//:sptth" ascii wide nocase
        $s6 = "/stnemhcatta/moc.ppadrocsid.ndc//:sptth" ascii wide nocase
        $s7 = "av9GaiV2dvkGch9SbvNmLkJ3bjNXak9yL6MHc0RHa" ascii wide
        $s8 = "WboNWY0RXYv02bj5CcwFGZy92YzlGZu4GZj9yL6MHc0RHa" ascii wide
    condition:
        uint16(0) == 0x5a4d and any of them
}

/*
rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_DisableTaskManager {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination indicative of disabling task manager"
    strings:
        $r1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide nocase
        $r2 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide nocase
        $k1 = "DisableTaskMgr" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (1 of ($r*) and 1 of ($k*))
}
*/

/*
rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_DisableExplorerHidden {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination indicative of disabling explorer displaying hidden files"
    strings:
        $r1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" ascii wide nocase
        $r2 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" ascii wide nocase
        $k1 = "Hidden" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (1 of ($r*) and 1 of ($k*))
}
*/

/*
rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_DisableSecurityCenter {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination indicative of disabling Security Center features"
    strings:
        $r1 = "SOFTWARE\\Microsoft\\Security Center" ascii wide nocase
        $k1 = "AntiVirusDisableNotify" ascii wide nocase
        $k2 = "FirewallDisableNotify" ascii wide nocase
        $k3 = "UpdatesDisableNotify" ascii wide nocase
        $k4 = "UacDisableNotify" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (1 of ($r*) and 1 of ($k*))
}
*/

/*
rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_DisableCMD {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination indicative of disabling command line"
    strings:
        $r1 = "Software\\Policies\\Microsoft\\Windows\\System" ascii wide nocase
        $k1 = "DisableCMD" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (1 of ($r*) and 1 of ($k*))
}
*/

/*
rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_NoRun {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination indicative of disabling command line"
    strings:
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii wide nocase
        $k1 = "NoRun" fullword ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (1 of ($r*) and 1 of ($k*))
}
*/

/*
rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_NoViewContextMenu {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination indicative of disabling command line"
    strings:
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii wide nocase
        $k1 = "NoViewContextMenu" fullword ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (1 of ($r*) and 1 of ($k*))
}
*/

/*
rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_Multi {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry keys / values combination indicative of impairing system"
    strings:
        $r1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide nocase
        $r2 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide nocase
        $r3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" ascii wide nocase
        $r4 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" ascii wide nocase
        $r5 = "Software\\Policies\\Microsoft\\Windows\\System" ascii wide nocase
        $r6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii wide nocase
        $r7 = "SOFTWARE\\Microsoft\\Security Center" ascii wide nocase
        $k1 = "DisableTaskMgr" ascii wide nocase
        $k2 = "Hidden" ascii wide nocase
        $k3 = "AntiVirusDisableNotify" ascii wide nocase
        $k4 = "FirewallDisableNotify" ascii wide nocase
        $k5 = "DisableCMD" ascii wide nocase
        $k6 = "NoRun" fullword ascii wide nocase
        $k7 = "NoViewContextMenu" fullword ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (3 of ($r*) and 3 of ($k*))
}
*/

rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_DisableWinDefender {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination indicative of disabling Windows Defedner features"
    strings:
        $r1 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
        $k1 = "DisableAntiSpyware" ascii wide
        $r2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" ascii wide nocase
        $k2 = "DisableBehaviorMonitoring" ascii wide
        $k3 = "DisableOnAccessProtection" ascii wide
        $k4 = "DisableScanOnRealtimeEnable" ascii wide
        $r3 = "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection" ascii wide nocase
        $k5 = "vDisableRealtimeMonitoring" ascii wide
        $r4 = "SOFTWARE\\Microsoft\\Windows Defender\\Spynet" ascii wide nocase
        $k6 = "SpyNetReporting" ascii wide
        $k7 = "SubmitSamplesConsent" ascii wide
        $r5 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii wide nocase
        $k8 = "TamperProtection" ascii wide
        $r6 = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" ascii wide nocase
        $k9 = "Add-MpPreference -ExclusionPath \"{0}\"" ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($r*) and 1 of ($k*))
}

rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_IExecuteCommandCOM {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding command execution via IExecuteCommand COM object"
    strings:
        $r1 = "Classes\\Folder\\shell\\open\\command" ascii wide nocase
        $k1 = "DelegateExecute" ascii wide
        $s1 = "/EXEFilename \"{0}" ascii wide
        $s2 = "/WindowState \"\"" ascii wide
        $s3 = "/PriorityClass \"\"32\"\" /CommandLine \"" ascii wide
        $s4 = "/StartDirectory \"" ascii wide
        $s5 = "/RunAs" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($r*) and 1 of ($k*)) or (all of ($s*)))
}

rule INDICATOR_SUSPICIOUS_EXE_WMI_EnumerateVideoDevice {
    meta:
        author = "ditekSHen"
        description = "Detects executables attemping to enumerate video devices using WMI"
    strings:
        $q1 = "Select * from Win32_CacheMemory" ascii wide nocase
        $d1 = "{860BB310-5D01-11d0-BD3B-00A0C911CE86}" ascii wide
        $d2 = "{62BE5D10-60EB-11d0-BD3B-00A0C911CE86}" ascii wide
        $d3 = "{55272A00-42CB-11CE-8135-00AA004BB851}" ascii wide
        $d4 = "SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\000" ascii wide nocase
        $d5 = "HardwareInformation.AdapterString" ascii wide
        $d6 = "HardwareInformation.qwMemorySize" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($q*) and 1 of ($d*)) or 3 of ($d*))
}

rule INDICATOR_SUSPICIOUS_EXE_DcRatBy {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing the string DcRatBy"
    strings:
        $s1 = "DcRatBy" ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_Anti_WinJail {
    meta:
        author = "ditekSHen"
        description = "Detects executables potentially checking for WinJail sandbox window"
    strings:
        $s1 = "Afx:400000:0" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_Anti_OldCopyPaste {
    meta:
        author = "ditekSHen"
        description = "Detects executables potentially checking for WinJail sandbox window"
    strings:
        $s1 = "This file can't run into Virtual Machines" wide
        $s2 = "This file can't run into Sandboxies" wide
        $s3 = "This file can't run into RDP Servers" wide
        $s4 = "Run without emulation" wide
        $s5 = "Run using valid operating system" wide
        $v1 = "SbieDll.dll" fullword wide
        $v2 = "USER" fullword wide
        $v3 = "SANDBOX" fullword wide
        $v4 = "VIRUS" fullword wide
        $v5 = "MALWARE" fullword wide
        $v6 = "SCHMIDTI" fullword wide
        $v7 = "CURRENTUSER" fullword wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or all of ($v*))
}

rule INDICATOR_SUSPICIOUS_EXE_Go_GoLazagne {
    meta:
        author = "ditekSHen"
        description = "Detects Go executables using GoLazagne"
    strings:
        $s1 = "/goLazagne/" ascii nocase
        $s2 = "Go build ID:" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_CSPROJ {
    meta:
        author = "ditekSHen"
        description = "Detects suspicious .CSPROJ files then compiled with msbuild"
    strings:
        $s1 = "ToolsVersion=" ascii
        $s2 = "/developer/msbuild/" ascii
        $x1 = "[DllImport(\"\\x" ascii
        $x2 = "VirtualAlloc(" ascii nocase
        $x3 = "CallWindowProc(" ascii nocase
    condition:
        uint32(0) == 0x6f72503c and (all of ($s*) and 2 of ($x*))
}

/*
rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_EnableLinkedConnections {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination ensuring mapped drives are available from an elevated prompt or process with UAC enabled. Observed in ransomware"
    strings:
        $r1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide nocase
        $k1 = "EnableLinkedConnections" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (1 of ($r*) and 1 of ($k*))
}
*/

/*
Too many FPs. Revise.
rule INDICATOR_SUSPICIOUS_References_EDR {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many AV and EDR software"
    strings:
        $s1 = "activeconsole" ascii wide nocase
        $s2 = "amsi.dll" ascii wide nocase
        $s3 = "anti malware" ascii wide nocase
        $s4 = "anti-malware" ascii wide nocase
        $s5 = "antimalware" ascii wide nocase
        $s6 = "anti virus" ascii wide nocase
        $s7 = "anti-virus" ascii wide nocase
        $s8 = "antivirus" ascii wide nocase
        $s9 = "appsense" ascii wide nocase
        $s10 = "authtap" ascii wide nocase
        $s11 = "avast" ascii wide nocase
        $s12 = "avecto" ascii wide nocase
        $s13 = "canary" ascii wide nocase
        $s14 = "carbonblack" ascii wide nocase
        $s15 = "carbon black" ascii wide nocase
        $s16 = "cb.exe" ascii wide nocase
        $s17 = "ciscoamp" ascii wide nocase
        $s18 = "cisco amp" ascii wide nocase
        $s19 = "countercept" ascii wide nocase
        $s20 = "countertack" ascii wide nocase
        $s21 = "cramtray" ascii wide nocase
        $s22 = "crssvc" ascii wide nocase
        $s23 = "crowdstrike" ascii wide nocase
        $s24 = "csagent" ascii wide nocase
        $s25 = "csfalcon" ascii wide nocase
        $s26 = "csshell" ascii wide nocase
        $s27 = "cybereason" ascii wide nocase
        $s28 = "cyclorama" ascii wide nocase
        $s29 = "cylance" ascii wide nocase
        $s30 = "cyoptics" ascii wide nocase
        $s31 = "cyupdate" ascii wide nocase
        $s32 = "cyvera" ascii wide nocase
        $s33 = "cyserver" ascii wide nocase
        $s34 = "cytray" ascii wide nocase
        $s35 = "darktrace" ascii wide nocase
        $s36 = "defendpoint" ascii wide nocase
        $s37 = "defender" ascii wide nocase
        $s38 = "eectrl" ascii wide nocase
        $s39 = "elastic" ascii wide nocase
        $s40 = "endgame" ascii wide nocase
        $s41 = "f-secure" ascii wide nocase
        $s42 = "forcepoint" ascii wide nocase
        $s43 = "fireeye" ascii wide nocase
        $s44 = "groundling" ascii wide nocase
        $s45 = "GRRservic" ascii wide nocase
        $s46 = "inspector" ascii wide nocase
        $s47 = "ivanti" ascii wide nocase
        $s48 = "kaspersky" ascii wide nocase
        $s49 = "lacuna" ascii wide nocase
        $s50 = "logrhythm" ascii wide nocase
        $s51 = "malware" ascii wide nocase
        $s52 = "mandiant" ascii wide nocase
        $s53 = "mcafee" ascii wide nocase
        $s54 = "morphisec" ascii wide nocase
        $s55 = "msascuil" ascii wide nocase
        $s56 = "msmpeng" ascii wide nocase
        $s57 = "nissrv" ascii wide nocase
        $s58 = "omni" ascii wide nocase
        $s59 = "omniagent" ascii wide nocase
        $s60 = "osquery" ascii wide nocase
        $s61 = "Palo Alto Networks" ascii wide nocase
        $s62 = "pgeposervice" ascii wide nocase
        $s63 = "pgsystemtray" ascii wide nocase
        $s64 = "privilegeguard" ascii wide nocase
        $s65 = "procwall" ascii wide nocase
        $s66 = "protectorservic" ascii wide nocase
        $s67 = "qradar" ascii wide nocase
        $s68 = "redcloak" ascii wide nocase
        $s69 = "secureworks" ascii wide nocase
        $s70 = "securityhealthservice" ascii wide nocase
        $s71 = "semlaunchsv" ascii wide nocase
        $s72 = "sentinel" ascii wide nocase
        $s73 = "sepliveupdat" ascii wide nocase
        $s74 = "sisidsservice" ascii wide nocase
        $s75 = "sisipsservice" ascii wide nocase
        $s76 = "sisipsutil" ascii wide nocase
        $s77 = "smc.exe" ascii wide nocase
        $s78 = "smcgui" ascii wide nocase
        $s79 = "snac64" ascii wide nocase
        $s80 = "sophos" ascii wide nocase
        $s81 = "splunk" ascii wide nocase
        $s82 = "srtsp" ascii wide nocase
        $s83 = "symantec" ascii wide nocase
        $s84 = "symcorpu" ascii wide nocase
        $s85 = "symefasi" ascii wide nocase
        $s86 = "sysinternal" ascii wide nocase
        $s87 = "sysmon" ascii wide nocase
        $s88 = "tanium" ascii wide nocase
        $s89 = "tda.exe" ascii wide nocase
        $s90 = "tdawork" ascii wide nocase
        $s91 = "tpython" ascii wide nocase
        $s92 = "vectra" ascii wide nocase
        $s93 = "wincollect" ascii wide nocase
        $s94 = "windowssensor" ascii wide nocase
        $s95 = "wireshark" ascii wide nocase
        $s96 = "threat" ascii wide nocase
        $s97 = "xagt.exe" ascii wide nocase
        $s98 = "xagtnotif.exe" ascii wide nocase
        $n1 = "Kaspersky Security Scan" ascii wide
    condition:
         uint16(0) == 0x5a4d and not any of ($n*) and 10 of ($s*) 
}
*/

rule INDICATOR_SUSPICIOUS_Sandbox_Evasion_FilesComb {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing specific set of files observed in sandob anti-evation, and Emotet"
    strings:
        $s1 = "c:\\take_screenshot.ps1" ascii wide nocase
        $s2 = "c:\\loaddll.exe" ascii wide nocase
        $s3 = "c:\\email.doc" ascii wide nocase
        $s4 = "c:\\email.htm" ascii wide nocase
        $s5 = "c:\\123\\email.doc" ascii wide nocase
        $s6 = "c:\\123\\email.docx" ascii wide nocase
        $s7 = "c:\\a\\foobar.bmp" ascii wide nocase
        $s8 = "c:\\a\\foobar.doc" ascii wide nocase
        $s9 = "c:\\a\\foobar.gif" ascii wide nocase
        $s10 = "c:\\symbols\\aagmmc.pdb" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 6 of them
}

rule INDICATOR_SUSPICIOUS_VM_Evasion_VirtDrvComb {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing combination of virtualization drivers"
    strings:
        $p1 = "prleth.sys" ascii wide
        $p2 = "prlfs.sys" ascii wide
        $p3 = "prlmouse.sys" ascii wide
        $p4 = "prlvideo.sys	" ascii wide
        $p5 = "prltime.sys" ascii wide
        $p6 = "prl_pv32.sys" ascii wide
        $p7 = "prl_paravirt_32.sys" ascii wide
        $vb1 = "VBoxMouse.sys" ascii wide
        $vb2 = "VBoxGuest.sys" ascii wide
        $vb3 = "VBoxSF.sys" ascii wide
        $vb4 = "VBoxVideo.sys" ascii wide
        $vb5 = "vboxdisp.dll" ascii wide
        $vb6 = "vboxhook.dll" ascii wide
        $vb7 = "vboxmrxnp.dll" ascii wide
        $vb8 = "vboxogl.dll" ascii wide
        $vb9 = "vboxoglarrayspu.dll" ascii wide
        $vb10 = "vboxoglcrutil.dll" ascii wide
        $vb11 = "vboxoglerrorspu.dll" ascii wide
        $vb12 = "vboxoglfeedbackspu.dll" ascii wide
        $vb13 = "vboxoglpackspu.dll" ascii wide
        $vb14 = "vboxoglpassthroughspu.dll" ascii wide
        $vb15 = "vboxservice.exe" ascii wide
        $vb16 = "vboxtray.exe" ascii wide
        $vb17 = "VBoxControl.exe" ascii wide
        $vp1 = "vmsrvc.sys" ascii wide
        $vp2 = "vpc-s3.sys" ascii wide
        $vw1 = "vmmouse.sys" ascii wide
        $vw2 = "vmnet.sys" ascii wide
        $vw3 = "vmxnet.sys" ascii wide
        $vw4 = "vmhgfs.sys" ascii wide
        $vw5 = "vmx86.sys" ascii wide
        $vw6 = "hgfs.sys" ascii wide
    condition:
         uint16(0) == 0x5a4d and (
             (2 of ($p*) and (2 of ($vb*) or 2 of ($vp*) or 2 of ($vw*))) or
             (2 of ($vb*) and (2 of ($p*) or 2 of ($vp*) or 2 of ($vw*))) or
             (2 of ($vp*) and (2 of ($p*) or 2 of ($vb*) or 2 of ($vw*))) or
             (2 of ($vw*) and (2 of ($p*) or 2 of ($vb*) or 2 of ($vp*)))
         )
}

rule INDICATOR_SUSPICIOUS_EXE_NoneWindowsUA {
    meta:
        author = "ditekSHen"
        description = "Detects Windows executables referencing non-Windows User-Agents"
    strings:
        $ua1 = "Mozilla/5.0 (Macintosh; Intel Mac OS" wide ascii
        $ua2 = "Mozilla/5.0 (iPhone; CPU iPhone OS" ascii wide
        $ua3 = "Mozilla/5.0 (Linux; Android " ascii wide
        $ua4 = "Mozilla/5.0 (PlayStation " ascii wide
        $ua5 = "Mozilla/5.0 (X11; " wide ascii
        $ua6 = "Mozilla/5.0 (Windows Phone " ascii wide
        $ua7 = "Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)" wide ascii
        $ua8 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0)" wide ascii
        $ua9 = "HTC_Touch_3G Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 7.11)" wide ascii
        $ua10 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows Phone OS 7.0; Trident/3.1; IEMobile/7.0; Nokia;N70)" wide ascii
        $ua11 = "Mozilla/5.0 (BlackBerry; U; BlackBerry " wide ascii
        $ua12 = "Mozilla/5.0 (iPad; CPU OS" wide ascii
        $ua13 = "Mozilla/5.0 (iPad; U;" ascii wide
        $ua14 = "Mozilla/5.0 (IE 11.0;" ascii wide
        $ua15 = "Mozilla/5.0 (Android;" ascii wide
        $ua16 = "User-Agent: Internal Wordpress RPC connection" ascii wide
    condition:
         uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_SUSPICIOUS_EXE_TooManyWindowsUA {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many varying, potentially fake Windows User-Agents"
    strings:
        $ua1 = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36" ascii wide
        $ua2 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36" ascii wide
        $ua3 = "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0" ascii wide
        $ua4 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0" ascii wide
        $ua5 = "Mozilla/5.0 (Windows NT 6.1; rv:27.3) Gecko/20130101 Firefox/27.3" ascii wide
        $ua6 = "Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US)" ascii wide
        $ua7 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" ascii wide
        $ua8 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)" ascii wide
        $ua9 = "Opera/12.0(Windows NT 5.2;U;en)Presto/22.9.168 Version/12.00" ascii wide
        $ua10 = "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14" ascii wide
        $ua11 = "Mozilla/5.0 (Windows NT 6.0; rv:2.0) Gecko/20100101 Firefox/4.0 Opera 12.14" ascii wide
        $ua12 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14" ascii wide
        $ua13 = "Opera/12.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.02" ascii wide
        $ua14 = "Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00" ascii wide
        $ua15 = "Opera/9.80 (Windows NT 5.1; U; zh-sg) Presto/2.9.181 Version/12.00" ascii wide
        $ua16 = "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7" ascii wide
        $ua17 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; tr-TR) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27" ascii wide
    condition:
         uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_SUSPICIOUS_VM_Evasion_MACAddrComb {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing virtualization MAC addresses"
    strings:
        $s1 = "00:03:FF" ascii wide nocase
        $s2 = "00:05:69" ascii wide nocase
        $s3 = "00:0C:29" ascii wide nocase
        $s4 = "00:16:3E" ascii wide nocase
        $s5 = "00:1C:14" ascii wide nocase
        $s6 = "00:1C:42" ascii wide nocase
        $s7 = "00:50:56" ascii wide nocase
        $s8 = "08:00:27" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 3 of them
}

/*
rule INDICATOR_SUSPICIOUS_CAPABILITY_CaptureScreenShot {
    meta:
        author = "ditekSHen"
        description = "Detects .NET executables with screen capture cabability"
    strings:
        $dll = "gdiplus.dll" ascii wide nocase
        $c1 = "gdipcreatebitmapfromhbitmap" ascii wide nocase
        $c2 = "gdipcreatebitmapfromscan0" ascii wide nocase
        $save = "gdipsaveimagetofile" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and ($dll and $save and (1 of ($c*)))
}
*/

rule INDICATOR_SUSPICIOUS_EXE_CC_Regex {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing credit card regular expressions"
    strings:
        // Amex / Express Card
        $s1 = "^3[47][0-9]{13}$" ascii wide nocase
        $s2 = "3[47][0-9]{13}$" ascii wide nocase
        $s3 = "37[0-9]{2}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase
        // BCGlobal
        $s4 = "^(6541|6556)[0-9]{12}$" ascii wide nocase
        // Carte Blanche Card
        $s5 = "^389[0-9]{11}$" ascii wide nocase
        // Diners Club Card
        $s6 = "^3(?:0[0-5]|[68][0-9])[0-9]{11}$" ascii wide nocase
        // Discover Card
        $s7 = "6(?:011|5[0-9]{2})[0-9]{12}$" ascii wide nocase
        $s8 = "6011\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase
        // Insta Payment Card
        $s9 = "^63[7-9][0-9]{13}$" ascii wide nocase
        // JCB Card
        $s10 = "^(?:2131|1800|35\\d{3})\\d{11}$" ascii wide nocase
        // KoreanLocalCard
        $s11 = "^9[0-9]{15}$" ascii wide nocase
        // Laser Card
        $s12 = "^(6304|6706|6709|6771)[0-9]{12,15}$" ascii wide nocase
        // Maestro Card
        $s13 = "^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$" ascii wide nocase
        // Mastercard
        $s14 = "5[1-5][0-9]{14}$" ascii wide nocase
        // Solo Card
        $s15 = "^(6334|6767)[0-9]{12}|(6334|6767)[0-9]{14}|(6334|6767)[0-9]{15}$" ascii wide nocase
        // Switch Card
        $s16 = "^(4903|4905|4911|4936|6333|6759)[0-9]{12}|(4903|4905|4911|4936|6333|6759)[0-9]{14}|(4903|4905|4911|4936|6333|6759)[0-9]{15}|564182[0-9]{10}|564182[0-9]{12}|564182[0-9]{13}|633110[0-9]{10}|633110[0-9]{12}|633110[0-9]{13}$" ascii wide nocase
        // Union Pay Card
        $s17 = "^(62[0-9]{14,17})$" ascii wide nocase
        // Visa Card
        $s18 = "4[0-9]{12}(?:[0-9]{3})?$" ascii wide nocase
        // Visa Master Card
        $s19 = "^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$" ascii wide nocase
        $s20 = "4[0-9]{3}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase
        $a21 = "^[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}"ascii wide nocase
    condition:
         (uint16(0) == 0x5a4d and 2 of them) or (4 of them)
}

rule INDICATOR_SUSPICIOUS_EXE_Discord_Regex {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing Discord tokens regular expressions"
    strings:
        $s1 = "[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_\\-]{27}|mfa\\.[a-zA-Z0-9_\\-]{84}" ascii wide nocase
    condition:
         (uint16(0) == 0x5a4d and all of them) or all of them
}

rule INDICATOR_SUSPICIOUS_EXE_References_VPN {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many VPN software clients. Observed in infosteslers"
    strings:
        $s1 = "\\VPN\\NordVPN" ascii wide nocase
        $s2 = "\\VPN\\OpenVPN" ascii wide nocase
        $s3 = "\\VPN\\ProtonVPN" ascii wide nocase
        $s4 = "\\VPN\\DUC\\" ascii wide nocase
        $s5 = "\\VPN\\PrivateVPN" ascii wide nocase
        $s6 = "\\VPN\\PrivateVPN" ascii wide nocase
        $s7 = "\\VPN\\EarthVPN" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 3 of them
}

/*
May generate FPs
rule INDICATOR_SUSPICIOUS_EXE_B64_URL {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing base64 encoded URL"
    strings:
        $s1 = "aHR0cHM6Ly9" ascii wide
        $s2 = "aHR0cDovL2" ascii wide
    condition:
         uint16(0) == 0x5a4d and 1 of them
}
*/

rule INDICATOR_SUSPICIOUS_EXE_VaultSchemaGUID {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing Windows vault credential objects. Observed in infostealers"
    strings:
        // Windows Secure Note
        $s1 = "2F1A6504-0641-44CF-8BB5-3612D865F2E5" ascii wide
        // Windows Web Password Credential
        $s2 = "3CCD5499-87A8-4B10-A215-608888DD3B55" ascii wide
        // Windows Credential Picker Protector
        $s3 = "154E23D0-C644-4E6F-8CE6-5069272F999F" ascii wide
        // Web Credentials
        $s4 = "4BF4C442-9B8A-41A0-B380-DD4A704DDB28" ascii wide
        // Windows Credentials
        $s5 = "77BC582B-F0A6-4E15-4E80-61736B6F3B29" ascii wide
        // Windows Domain Certificate Credential
        $s6 = "E69D7838-91B5-4FC9-89D5-230D4D4CC2BC" ascii wide
        // Windows Domain Password Credential
        $s7 = "3E0E35BE-1B77-43E7-B873-AED901B6275B" ascii wide
        // Windows Extended Credential
        $s8 = "3C886FF3-2669-4AA2-A8FB-3F6759A77548" ascii wide
    condition:
         uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_SUSPICIOUS_AntiVM_UNK01 {
    meta:
        author = "ditekSHen"
        description = "Detects memory artifcats referencing specific combination of anti-VM checks"
    strings:
        $s1 = "vmci.s" fullword ascii wide
        $s2 = "vmmemc" fullword ascii wide
        $s3 = "qemu-ga.exe" fullword ascii wide
        $s4 = "qga.exe" fullword ascii wide
        $s5 = "windanr.exe" fullword ascii wide
        $s6 = "vboxservice.exe" fullword ascii wide
        $s7 = "vboxtray.exe" fullword ascii wide
        $s8 = "vmtoolsd.exe" fullword ascii wide
        $s9 = "prl_tools.exe" fullword ascii wide
        $s10 = "7869.vmt" fullword ascii wide
        $s11 = "qemu" fullword ascii wide
        $s12 = "virtio" fullword ascii wide
        $s13 = "vmware" fullword ascii wide
        $s14 = "vbox" fullword ascii wide
        $s15 = "%systemroot%\\system32\\ntdll.dll" fullword ascii wide
    condition:
         uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_AntiVM_WMIC {
    meta:
        author = "ditekSHen"
        description = "Detects memory artifcats referencing WMIC commands for anti-VM checks"
    strings:
        $s1 = "wmic process where \"name like '%vmwp%'\"" ascii wide nocase
        $s2 = "wmic process where \"name like '%virtualbox%'\"" ascii wide nocase
        $s3 = "wmic process where \"name like '%vbox%'\"" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_SUSPICIOUS_EnableSMBv1 {
    meta:
        author = "ditekSHen"
        description = "Detects binaries with PowerShell command enabling SMBv1"
    strings:
        $s1 = "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_SUSPICIOUS_EnableNetworkDiscovery {
    meta:
        author = "ditekSHen"
        description = "Detects binaries manipulating Windows firewall to enable permissive network discovery"
    strings:
        $s1 = "netsh advfirewall firewall set rule group=\"Network Discovery\" new enable=Yes" ascii wide nocase 
        $s2 = "netsh advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=Yes" ascii wide nocase 
    condition:
         uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_References_AuthApps {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many authentication apps. Observed in information stealers"
    strings:
        $s1 = "WinAuth\\winauth.xml" ascii wide nocase
        $s2 = "Authy Desktop\\Local" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_RDP {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination manipulating RDP / Terminal Services"
    strings:
        // Beginning with Windows Server 2008 and Windows Vista, this policy no longer has any effect
        // https://docs.microsoft.com/en-us/windows/win32/msi/enableadmintsremote
        $r1 = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" ascii wide nocase
        $k1 = "EnableAdminTSRemote" fullword ascii wide nocase
        // Whether basic Terminal Services functions are enabled
        $r2 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide nocase
        $k2 = "TSEnabled" fullword ascii wide nocase
        // Terminal Device Driver Attributes
        // Terminal Services hosts and configurations
        $r3 = "SYSTEM\\CurrentControlSet\\Services\\TermDD" ascii wide nocase
        $r4 = "SYSTEM\\CurrentControlSet\\Services\\TermService" ascii wide nocase
        $k3 = "Start" fullword ascii wide nocase
        // Allows or denies connecting to Terminal Services
        $r5 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide nocase
        $k4 = "fDenyTSConnections" fullword ascii wide nocase
        // RDP Port Number
        $r6 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\RDPTcp" ascii wide nocase
        $r7 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp" ascii wide nocase
        $r8 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii wide nocase
        $k5 = "PortNumber" fullword ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 5 of ($r*) and 3 of ($k*)
}

// http://undoc.airesoft.co.uk/

rule INDICATOR_SUSPICIOUS_EXE_Undocumented_WinAPI_Kerberos {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing undocumented kerberos Windows APIs and obsereved in malware"
    strings:
        // Undocumented Kerberos-related functions
        // Reference: https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/ (KdcSponge)
        // Reference: https://us-cert.cisa.gov/ncas/current-activity/2021/11/19/updated-apt-exploitation-manageengine-adselfservice-plus
        // New Sample: e391c2d3e8e4860e061f69b894cf2b1ba578a3e91de610410e7e9fa87c07304c
        $kdc1 = "KdcVerifyEncryptedTimeStamp" ascii wide nocase
        $kdc2 = "KerbHashPasswordEx3" ascii wide nocase
        $kdc3 = "KerbFreeKey" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and all of ($kdc*)
}

rule INDICATOR_SUSPICIOUS_EXE_NKN_BCP2P {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing NKN Blockchain P2P network"
    strings:
        $x1 = "/nknorg/nkn-sdk-go." ascii
        $x2 = "://seed.nkn.org" ascii
        $x3 = "/nknorg/nkn/" ascii
        $s1 = ").NewNanoPayClaimer" ascii
        $s2 = ").IncrementAmount" ascii
        $s3 = ").BalanceByAddress" ascii
        $s4 = ").TransferName" ascii
        $s5 = ".GetWsAddr" ascii
        $s6 = ".GetNodeStateContext" ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($x*) or all of ($s*))
}

rule INDICATOR_SUSPICIOUS_EXE_References_PasswordManagers {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many Password Manager software clients. Observed in infostealers"
    strings:
        $s1 = "1Password\\" ascii wide nocase
        $s2 = "Dashlane\\" ascii wide nocase
        $s3 = "nordpass*.sqlite" ascii wide nocase
        $s4 = "RoboForm\\" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_EXE_WirelessNetReccon {
    meta:
        author = "ditekSHen"
        description = "Detects executables with interest in wireless interface using netsh"
    strings:
        $s1 = "netsh wlan show profile" ascii wide nocase
        $s2 = "netsh wlan show profile name=" ascii wide nocase
        $s3 = "netsh wlan show networks mode=bssid" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_References_GitConfData {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing potentially confidential GIT artifacts. Observed in infostealer"
    strings:
        $s1 = "GithubDesktop\\Local Storage" ascii wide nocase
        $s2 = "GitHub Desktop\\Local Storage" ascii wide nocase
        $s3 = ".git-credentials" ascii wide
        $s4 = ".config\\git\\credentials" ascii wide
        $s5 = ".gitconfig" ascii wide
    condition:
         uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_SUSPICIOUS_EXE_Reversed {
    meta:
        author = "ditekSHen"
        description = "Detects reversed executables. Observed N-stage drop"
    strings:
        $s1 = "edom SOD ni nur eb tonnac margorp sihT" ascii
    condition:
         uint16(filesize-0x2) == 0x4d5a and $s1
}