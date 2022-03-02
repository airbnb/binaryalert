rule win_joanap_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.joanap."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.joanap"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 0f8491030000 8d4c2448 51 ff15???????? 8d542418 8d442448 52 }
            // n = 7, score = 100
            //   0f8491030000         | je                  0x397
            //   8d4c2448             | lea                 ecx, dword ptr [esp + 0x48]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d542418             | lea                 edx, dword ptr [esp + 0x18]
            //   8d442448             | lea                 eax, dword ptr [esp + 0x48]
            //   52                   | push                edx

        $sequence_1 = { 8b5c2408 56 8b742410 57 8b7c241c 57 6820bf0200 }
            // n = 7, score = 100
            //   8b5c2408             | mov                 ebx, dword ptr [esp + 8]
            //   56                   | push                esi
            //   8b742410             | mov                 esi, dword ptr [esp + 0x10]
            //   57                   | push                edi
            //   8b7c241c             | mov                 edi, dword ptr [esp + 0x1c]
            //   57                   | push                edi
            //   6820bf0200           | push                0x2bf20

        $sequence_2 = { be???????? 668b16 6aff 52 }
            // n = 4, score = 100
            //   be????????           |                     
            //   668b16               | mov                 dx, word ptr [esi]
            //   6aff                 | push                -1
            //   52                   | push                edx

        $sequence_3 = { 8a8900ba2c00 32cb 8a5c243c 884806 8a8f00ba2c00 32cb 884807 }
            // n = 7, score = 100
            //   8a8900ba2c00         | mov                 cl, byte ptr [ecx + 0x2cba00]
            //   32cb                 | xor                 cl, bl
            //   8a5c243c             | mov                 bl, byte ptr [esp + 0x3c]
            //   884806               | mov                 byte ptr [eax + 6], cl
            //   8a8f00ba2c00         | mov                 cl, byte ptr [edi + 0x2cba00]
            //   32cb                 | xor                 cl, bl
            //   884807               | mov                 byte ptr [eax + 7], cl

        $sequence_4 = { 8b4c2410 41 83c504 894c2410 8b442414 83c018 47 }
            // n = 7, score = 100
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   41                   | inc                 ecx
            //   83c504               | add                 ebp, 4
            //   894c2410             | mov                 dword ptr [esp + 0x10], ecx
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   83c018               | add                 eax, 0x18
            //   47                   | inc                 edi

        $sequence_5 = { 33c2 33d2 8a54241a 8b1c9500bf2c00 8bd1 }
            // n = 5, score = 100
            //   33c2                 | xor                 eax, edx
            //   33d2                 | xor                 edx, edx
            //   8a54241a             | mov                 dl, byte ptr [esp + 0x1a]
            //   8b1c9500bf2c00       | mov                 ebx, dword ptr [edx*4 + 0x2cbf00]
            //   8bd1                 | mov                 edx, ecx

        $sequence_6 = { ffd5 83c40c 8d4c240c 8d942454030000 51 52 ff15???????? }
            // n = 7, score = 100
            //   ffd5                 | call                ebp
            //   83c40c               | add                 esp, 0xc
            //   8d4c240c             | lea                 ecx, dword ptr [esp + 0xc]
            //   8d942454030000       | lea                 edx, dword ptr [esp + 0x354]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_7 = { 7462 57 b941000000 33c0 8d7c2410 68???????? f3ab }
            // n = 7, score = 100
            //   7462                 | je                  0x64
            //   57                   | push                edi
            //   b941000000           | mov                 ecx, 0x41
            //   33c0                 | xor                 eax, eax
            //   8d7c2410             | lea                 edi, dword ptr [esp + 0x10]
            //   68????????           |                     
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_8 = { 66897d04 56 c74500b2000000 e8???????? 83c410 83f8ff 7428 }
            // n = 7, score = 100
            //   66897d04             | mov                 word ptr [ebp + 4], di
            //   56                   | push                esi
            //   c74500b2000000       | mov                 dword ptr [ebp], 0xb2
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   83f8ff               | cmp                 eax, -1
            //   7428                 | je                  0x2a

        $sequence_9 = { 6a00 6a00 8974243c 897c2438 c744242000000000 c7442424a0860100 }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8974243c             | mov                 dword ptr [esp + 0x3c], esi
            //   897c2438             | mov                 dword ptr [esp + 0x38], edi
            //   c744242000000000     | mov                 dword ptr [esp + 0x20], 0
            //   c7442424a0860100     | mov                 dword ptr [esp + 0x24], 0x186a0

    condition:
        7 of them and filesize < 270336
}