rule MAL_Shark_Aug_2021_1
{
   meta:
      description = "Detect Shark backdoor used by Hexane group (aka Siamesekitten)"
      author = "Arkbird_SOLG"
      reference = "https://www.clearskysec.com/siamesekitten/"
      date = "2021-08-18"
      hash1 = "89ab99f5721b691e5513f4192e7c96eb0981ddb6c2d2b94c1a32e2df896397b8"
      hash2 = "f6ae4f4373510c4e096fab84383b547c8997ccf3673c00660df8a3dc9ed1f3ca"
      hash3 = "44faf11719b3a679e7a6dd5db40033ec4dd6e1b0361c145b81586cb735a64112"
      hash4 = "2f2ef9e3f6db2146bd277d3c4e94c002ecaf7deaabafe6195fddabc81a8ee76c"
      tlp = "White"
      adversary = "Hexane"
   strings:
        $s1 = { 7b 00 22 00 44 00 61 00 74 00 61 00 22 00 3a 00 5b 00 22 00 00 07 22 00 [0-8] 5d 00 7d }
        $s2 = "application/json" fullword wide
        $s3 = { 40 00 45 00 43 00 48 00 4f 00 20 00 4f 00 46 00 46 00 0a 00 00 1d 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 49 00 4d 00 20 00 22 00 00 17 22 00 20 00 2f 00 46 00 20 00 3e 00 20 00 6e 00 75 00 6c 00 0a 00 00 2b 70 00 69 00 6e 00 67 00 20 00 [12-28] 00 20 00 6e 00 75 00 6c }
        $s4 = { 2a 00 65 00 78 00 65 00 00 0b 2a 00 70 00 72 00 6f 00 63 00 00 07 2a 00 6b 00 6c 00 00 07 64 00 69 00 72 00 00 11 66 00 69 00 6c 00 65 00 3a 00 2f 00 2f 00 2f }
        $s5 = { 16 0a 2b 13 02 06 02 06 91 1f 2a 28 ?? 00 00 0a 61 d2 9c 06 17 58 0a 06 02 8e 69 }
        $s6 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography" fullword wide
        $s7 = { 65 00 63 00 68 00 6f 00 20 00 [2-10] 20 00 7c 00 20 00 64 00 65 00 6c 00 20 00 [2-10] 2e 00 62 00 61 00 74 00 00 0f [2-10] 00 2e 00 62 00 61 00 74 }
   condition:
      uint16(0) == 0x5A4D and filesize > 15KB and 6 of ($s*)
}
