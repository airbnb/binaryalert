import "pe"

rule APT_NK_Lazarus_Stealer_ScreenCapture_June_2020_1 {
   meta:
      description = "Detect ScreenCapture malware used by Lazarus APT"
      author = "Arkbird_SOLG, James_inthe_box"
      reference = "https://twitter.com/GR_CTI/status/1275164880992186371"
      date = "2020-06-23"
      hash1 = "6caa98870efd1097ee13ae9c21c6f6c9202a19ad049a9e65c60fce5c889dc4c8"
   strings:
      $s1 = "E:\\workspace\\VS\\crat_2\\client\\Build\\Win32\\DllRelease\\ScreenCapture_Win32_DllRelease.pdb" fullword ascii
      $s2 = "CloseHandle ScreenCaptureMutex failure! %d" fullword ascii
      $s3 = "ScreenCapture_Win32_DllRelease.dll" fullword ascii
      $s4 = "ScreenCaptureMutex already created! %s\n" fullword ascii
      $s5 = "Capturing screen...\n" fullword ascii
      $s6 = "%s\\P%02d%lu.tmp" fullword ascii
      $s7 = "ScreenCaptureThread finished!" fullword ascii
      $s8 = "ScreenCaptureThread started!" fullword ascii
      $s9 = "ScreenCapture start time set to %llu" fullword ascii
      $s10 = "ScreenCaptureMutex already created! %s\n" fullword ascii
      $s11 = "Major=%d, Minor=%d, Build=%d, Arch=%d" fullword ascii
      $s12 = "Can't create file %s, errno = %d, nCreateRetryCount = %d" fullword ascii
      $s13 = "ExploreDirectory, csDirectoryPath = %s, dwError=%d" fullword ascii
      $s14 = "[END] ScreenCaptureThread terminated!" fullword ascii
      $s15 = { 25 00 2d 00 32 00 30 00 73 00 20 00 20 00 20 00 25 00 31 00 30 00 6c 00 6c 00 75 00 20 00 62 00 79 00 74 00 65 00 73 } /* \t%-20s   %10llu bytes */
      $s16 = { 57 00 72 00 6f 00 74 00 65 00 20 00 25 00 64 00 20 00 62 00 79 00 74 00 65 00 73 00 20 00 74 00 6f 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 } /* Wrote %d bytes to file %s */
      $s17 = "Entered Windows direcotry, skipping..." fullword ascii
      $s18 = "Found %d entries." fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and 14 of them 
}

rule APT_NK_Lazarus_Stealer_KeyLog_June_2020_1 {
   meta:
      description = "Detect keylog malware used by Lazarus APT"
      author = "Arkbird_SOLG, James_inthe_box"
      reference = "https://twitter.com/GR_CTI/status/1275164880992186371"
      date = "2020-06-23"
      hash1 = "6d461bf3e3ca68b2d6d850322b79d5e3e647b0d515cb10449935bf6d77d7d5f2"
   strings:
      $s1 = "E:\\workspace\\VS\\crat_2\\client\\Build\\Win32\\DllRelease\\KeyLog_Win32_DllRelease.pdb" fullword ascii
      $s2 = "CloseHandle KeyLogMutex failure! %d" fullword ascii
      $s3 = "KeyLog_Win32_DllRelease.dll" fullword ascii
      $s4 = "Key Log Mutex already created! %s\n" fullword ascii
      $s5 = "Unable to GetProcAddress of GetAsyncKeyState" fullword ascii
      $s6 = "KeyLogThread finished!" fullword ascii
      $s7 = "KeyLogThread started!" fullword ascii
      $s8 = "Major=%d, Minor=%d, Build=%d, Arch=%d" fullword ascii
      $s9 = "Can't create file %s, errno = %d, nCreateRetryCount = %d" fullword ascii
      $s10 = "ExploreDirectory, csDirectoryPath = %s, dwError=%d" fullword ascii
      $s11 = "[END] KeyLogThread terminated!" fullword ascii 
      $s12 = { 25 00 2d 00 32 00 30 00 73 00 20 00 20 00 20 00 25 00 31 00 30 00 6c 00 6c 00 75 00 20 00 62 00 79 00 74 00 65 00 73 } /* \t%-20s   %10llu bytes */
      $s13 = { 57 00 72 00 6f 00 74 00 65 00 20 00 25 00 64 00 20 00 62 00 79 00 74 00 65 00 73 00 20 00 74 00 6f 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 } /* Wrote %d bytes to file %s */
      $s14 = "Entered Windows direcotry, skipping..." fullword ascii
      $s15 = "Found %d entries." fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and 11 of them 
}

rule APT_NK_Lazarus_Stealer_Generic_June_2020_1 {
   meta:
      description = "Detect stealers used by Lazarus APT by common strings"
      author = "Arkbird_SOLG, James_inthe_box"
      reference = "https://twitter.com/GR_CTI/status/1275164880992186371"
      date = "2020-06-23"
      hash1 = "6d461bf3e3ca68b2d6d850322b79d5e3e647b0d515cb10449935bf6d77d7d5f2"
      hash2 = "6caa98870efd1097ee13ae9c21c6f6c9202a19ad049a9e65c60fce5c889dc4c8"
   strings:
      $s1 = "E:\\workspace\\VS\\crat_2\\client\\Build\\Win32\\DllRelease" fullword ascii
      $s2 = "Mutex failure! %d" fullword ascii
      $s3 = "Win32_DllRelease.dll" fullword ascii
      $s4 = "Mutex already created! %s\n" fullword ascii
      $s5 = "[END]" fullword ascii
      $s6 = "Thread finished!" fullword ascii
      $s7 = "Thread started!" fullword ascii
      $s8 = "Major=%d, Minor=%d, Build=%d, Arch=%d" fullword ascii
      $s9 = "Can't create file %s, errno = %d, nCreateRetryCount = %d" fullword ascii
      $s10 = "ExploreDirectory, csDirectoryPath = %s, dwError=%d" fullword ascii
      $s11 = "Thread terminated!" fullword ascii 
      $s12 = { 25 00 2d 00 32 00 30 00 73 00 20 00 20 00 20 00 25 00 31 00 30 00 6c 00 6c 00 75 00 20 00 62 00 79 00 74 00 65 00 73 } /* \t%-20s   %10llu bytes */
      $s13 = { 57 00 72 00 6f 00 74 00 65 00 20 00 25 00 64 00 20 00 62 00 79 00 74 00 65 00 73 00 20 00 74 00 6f 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 } /* Wrote %d bytes to file %s */
      $s14 = "Entered Windows direcotry, skipping..." fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and 11 of them 
}
