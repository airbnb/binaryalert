import "pe"

rule danabot_main {
   meta:
      description = "Detects the main component of DanaBot"
      author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
      reference = "https://github.com/f0wl/danaConfig"
      date = "2021-11-14"
      tlp = "WHITE"
      hash1 = "77ff83cc49d6c1b71c474a17eeaefad0f0a71df0a938190bf9a9a7e22531c292"
      hash2 = "e7c9951f26973c3915ffadced059e629390c2bb55b247e2a1a95effbd7d29204"
      hash3 = "ad0ccba36cef1de383182f866478abcd8b91f8e060d03e170987431974dc861e"
   
   strings:
      $s1 = "TProxyTarget" ascii
      $s2 = "TPasswords" ascii

      $w1 = "FILEZILLA1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ" wide
      $w2 = "82BD0E67-9FEA-4748-8672-D5EFE5B779B0" wide //CLSID C:\Windows\system32\wincredui.dll
      $w3 = "F:\\b_system\\FS_Morff\\FS_Temp\\" wide
      $w4 = "MiniInit:Except" wide
      $w5 = "Except:StartConnectSystem" wide
      $w6 = "StealerInformation" wide
      $w7 = "www.google.com/Please log in to your Gmail account" wide

   condition:
      uint16(0) == 0x5a4d
      and filesize > 4000KB
      and filesize < 25000KB 
      and pe.imphash() == "908afa7baa08116e817d0ade28b27ef3"
      and 4 of them
}
