/*
   YARA Rule Set
   Author: Arkbird_SOLG
   Date: 2019-11-29
   Reference: https://twitter.com/Rmy_Reserve/status/1197448735422238721
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT_DustSquad_PE_Nov19_1 {
   meta:
      description = "Detection Rule for APT DustSquad campaign Nov19"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Rmy_Reserve/status/1197448735422238721"
      date = "2019-11-29"
      hash1 = "105402dd65ec1c53b6db68a0e21fcee5b72e161bc3b53e644695a4c9fae32909"
   strings:
      $x1 = "The credentials supplied were not complete, and could not be verified. Additional information can be returned from the context.4" wide
      $s2 = "The logon attempt failed;The credentials supplied to the package were not recognized4No credentials are available in the securit" wide
      $s3 = "Address type not supported.\"%s: Circular links are not allowed\"Not enough data in buffer. (%d/%d)" fullword wide
      $s4 = "@TList<System.DateUtils.TLocalTimeZone.TYearlyChanges>.TEmptyFunc" fullword ascii
      $s5 = "Error getting SSL method.%Error setting File Descriptor for SSL!Error binding data to SSL socket.'Maximum number of line allowed" wide
      $s6 = "Checksum error in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s7 = "Download: " fullword wide
      $s8 = "An attempt was made by this server to make a Kerberos constrained delegation request for a target outside of the server's realm." wide
      $s9 = "D:\\Projects\\WinRAR\\rar\\build\\rar32\\Release\\RAR.pdb" fullword ascii
      $s10 = " computersystem get Name /format:list" fullword wide
      $s11 = "Enter password (will not be echoed) for %s: " fullword wide
      $s12 = "Remove: " fullword wide
      $s13 = "rarinfo.log" fullword wide
      $s14 = "?WThe given \"%s\" local time is invalid (situated within the missing period prior to DST).8String index out of range (%d).  Mus" wide
      $s15 = "OnExecuteH}H" fullword ascii
      $s16 = "ffffffffffffffg" fullword ascii /* reversed goodware string 'gffffffffffffff' */
      $s17 = "Successfull API call7Not enough memory is available to complete this request" wide
      $s18 = "The handle specified is invalid'The function reques" wide
      $s19 = "1????????.*" wide
      $s20 = "/d.php?servers" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      ( pe.imphash() == "9a622f807282a29fb32811b734622622" or ( 1 of ($x*) or 4 of them ) )
}

rule APT_DustSquad_BAT_Nov19_1 {
   meta:
      description = "Detection Rule for APT DustSquad campaign Nov19"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Rmy_Reserve/status/1197448735422238721"
      date = "2019-11-29"
      hash1 = "500983f7e9fb67bbe6651a5780e637474f1cd813600d4ae8b362dcf27d23b3d2"
   strings:
      $x1 = "if exist \"C:\\Users\\admin\\AppData\\Local\\Temp\\62fb5aa21f62e92586829520078c2561.exe\" (" fullword ascii
      $x2 = "del \"C:\\Users\\admin\\AppData\\Local\\Temp\\62fb5aa21f62e92586829520078c2561.exe\"" fullword ascii
      $x3 = "del \"C:\\Users\\admin\\AppData\\Local\\Temp\\s.bat\"" fullword ascii
      $s4 = "ping 192.168.100.84 -n 1 > nul" fullword ascii
      $s5 = "for /L %%n in (1,1,50) do (" fullword ascii
      $s6 = "chcp 1251 > nul" fullword ascii
      $s7 = ") else (" fullword ascii
      $s8 = "62fb5aa21f62e9258682952" ascii
   condition:
      uint16(0) == 0x6863 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule APT_DustSquad_PE_Nov19_2 {
   meta:
      description = "Detection Rule for APT DustSquad campaign Nov19"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Rmy_Reserve/status/1197448735422238721"
      date = "2019-11-29"
      hash1 = "f5941f3d8dc8d60581d4915d06d56acba74f3ffad543680a85037a8d3bf3f8bc"
   strings:
      $x1 = "The credentials supplied were not complete, and could not be verified. Additional information can be returned from the context.4" wide
      $x2 = "The domain controller certificate used for smartcard logon has been revoked. Please contact your system administrator with the c" wide
      $s3 = "VTDictionary<System.Word,System.DateUtils.TLocalTimeZone.TYearlyChanges>.TKeyEnumeratorxsN" fullword ascii
      $s4 = ";The certificate chain was issued by an untrusted authority.7The message received was unexpected or badly formatted.;An unknown " wide
      $s5 = "The logon attempt failed;The credentials supplied to the package were not recognized4No credentials are available in the securit" wide
      $s6 = "8The message supplied for verification is out of sequence3No authority could be contacted for authentication.UThe function compl" wide
      $s7 = "The security context could not be established due to a failure in the requested quality of service (e.g. mutual authentication o" wide
      $s8 = "Error reading %s%s%s: %s\"Character index out of bounds (%d)" fullword wide
      $s9 = "OnExecutel" fullword ascii
      $s10 = "?WThe given \"%s\" local time is invalid (situated within the missing period prior to DST).8String index out of range (%d).  Mus" wide
      $s11 = "Address type not supported.\"%s: Circular links are not allowed\"Not enough data in buffer. (%d/%d)" fullword wide
      $s12 = "@TList<System.DateUtils.TLocalTimeZone.TYearlyChanges>.TEmptyFunc !@" fullword ascii
      $s13 = "dTList<System.DateUtils.TPair<System.Word,System.DateUtils.TLocalTimeZone.TYearlyChanges>>.TEmptyFunc !@" fullword ascii
      $s14 = "EVP_PKEY_CTX_get_operation" fullword wide
      $s15 = "http://www.borland.com/namespaces/Types" fullword wide
      $s16 = "OnGetPassword" fullword ascii
      $s17 = "OnGetPasswordExp" fullword ascii
      $s18 = "a1.exe" fullword ascii
      $s19 = "EIdSocksServerCommandError " fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      ( pe.imphash() == "7b3af4ed73c83b1a16f6f299b3eb654e" or ( 1 of ($x*) or 4 of them ) )
}

/* Super Rules ------------------------------------------------------------- */

rule SR_APT_DustSquad_PE_Nov19 {
   meta:
      description = "Super Rule for APT DustSquad campaign Nov19"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/Rmy_Reserve/status/1197448735422238721"
      date = "2019-11-29"
   strings:
      $s1 = "EVP_PKEY_get1_DSA" fullword wide
      $s2 = "?WThe given \"%s\" local time is invalid (situated within the missing period prior to DST).8String index out of range (%d).  Mus" wide
      $s3 = "Address type not supported.\"%s: Circular links are not allowed\"Not enough data in buffer. (%d/%d)" fullword wide
      $s4 = "EVP_PKEY_CTX_get_operation" fullword wide
      $s5 = "OnGetPassword" fullword ascii
      $s6 = "Mozilla/5.0" fullword wide
      $s7 = ",Custom variant type (%s%.4x) is out of range/Custom variant type (%s%.4x) already used by %s*Custom variant type (%s%.4x) is no" wide
      $s8 = "WorkTarget" fullword ascii
      $s9 = "Generics.Collections}TList<System.DateUtils.TPair<System.Word,System.DateUtils.TLocalTimeZone.TYearlyChanges>>.:1" fullword ascii
      $s10 = "EVP_PKEY_encrypt_old" fullword wide
      $s11 = "EVP_PKEY_CTX_get0_pkey" fullword wide
      $s12 = "EVP_PKEY_encrypt_init" fullword wide
      $s13 = "EVP_PKEY_encrypt" fullword wide
      $s14 = "EVP_PKEY_CTX_get0_peerkey" fullword wide
      $s15 = "EVP_PKEY_get0" fullword wide
      $s16 = "X509_PUBKEY_get" fullword wide
      $s17 = "EVP_PKEY_CTX_get_cb" fullword wide
      $s18 = "EVP_PKEY_meth_set_encrypt" fullword wide
      $s19 = "EVP_PKEY_get1_RSA" fullword wide 
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}
