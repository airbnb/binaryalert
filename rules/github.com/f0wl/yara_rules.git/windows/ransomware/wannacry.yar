rule WannaCry : ransomware {
   meta:
    description = "Detects WannaCry Ransomware" 
    author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
    reference = "https://dissectingmalwa.re/third-times-the-charm-analysing-wannacry-samples.html"
    date = "2019-07-28"
    hash1 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
      
   strings:
    $name = "WanaCrypt0r" wide
    $langNote = "msg/m_english.wnry" ascii
    
    $s1 = "s.wnry" ascii
    $s2 = "taskdl.exe" ascii
    $s3 = "taskse.exe" ascii
    $s4 = "<!-- Windows 10 -->" ascii
    $s5 = "taskse.exed*" ascii
    $s6 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii

   condition:
      uint16(0) == 0x5a4d and filesize < 4MB 
      and $name
      and $langNote
      and 3 of ($s*)
} 
 
