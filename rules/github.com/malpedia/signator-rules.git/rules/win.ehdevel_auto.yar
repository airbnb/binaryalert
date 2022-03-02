rule win_ehdevel_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.ehdevel."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ehdevel"
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
        $sequence_0 = { 52 6800140000 8d8424b0210000 50 8d8c24b4110000 51 }
            // n = 6, score = 100
            //   52                   | push                edx
            //   6800140000           | push                0x1400
            //   8d8424b0210000       | lea                 eax, dword ptr [esp + 0x21b0]
            //   50                   | push                eax
            //   8d8c24b4110000       | lea                 ecx, dword ptr [esp + 0x11b4]
            //   51                   | push                ecx

        $sequence_1 = { 8d4c2404 6800040000 51 e8???????? 83c40c 68???????? 8d942404100000 }
            // n = 7, score = 100
            //   8d4c2404             | lea                 ecx, dword ptr [esp + 4]
            //   6800040000           | push                0x400
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   8d942404100000       | lea                 edx, dword ptr [esp + 0x1004]

        $sequence_2 = { 8d8de0f9ffff 51 ff15???????? 8bf0 83feff 0f84c8010000 8d95e8fbffff }
            // n = 7, score = 100
            //   8d8de0f9ffff         | lea                 ecx, dword ptr [ebp - 0x620]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   0f84c8010000         | je                  0x1ce
            //   8d95e8fbffff         | lea                 edx, dword ptr [ebp - 0x418]

        $sequence_3 = { e8???????? 83c40c 68???????? 8d85f8f7ffff }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   8d85f8f7ffff         | lea                 eax, dword ptr [ebp - 0x808]

        $sequence_4 = { 8bec 83e4f8 83ec3c 56 68???????? e8???????? }
            // n = 6, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83e4f8               | and                 esp, 0xfffffff8
            //   83ec3c               | sub                 esp, 0x3c
            //   56                   | push                esi
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_5 = { ff15???????? 85c0 0f84b7000000 8d4324 50 8d85f8f7ffff }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84b7000000         | je                  0xbd
            //   8d4324               | lea                 eax, dword ptr [ebx + 0x24]
            //   50                   | push                eax
            //   8d85f8f7ffff         | lea                 eax, dword ptr [ebp - 0x808]

        $sequence_6 = { 50 e8???????? 83c424 8d8c24a8010000 51 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   8d8c24a8010000       | lea                 ecx, dword ptr [esp + 0x1a8]
            //   51                   | push                ecx

        $sequence_7 = { 8b85dcefffff 57 8d95f4f7ffff 52 50 }
            // n = 5, score = 100
            //   8b85dcefffff         | mov                 eax, dword ptr [ebp - 0x1024]
            //   57                   | push                edi
            //   8d95f4f7ffff         | lea                 edx, dword ptr [ebp - 0x80c]
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_8 = { e8???????? 83c40c f68580f3ffff10 7459 8d95f0fdffff 52 ff15???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   f68580f3ffff10       | test                byte ptr [ebp - 0xc80], 0x10
            //   7459                 | je                  0x5b
            //   8d95f0fdffff         | lea                 edx, dword ptr [ebp - 0x210]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_9 = { 50 e8???????? 83c404 8b85d4f7ffff 39b5e8f7ffff 7306 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b85d4f7ffff         | mov                 eax, dword ptr [ebp - 0x82c]
            //   39b5e8f7ffff         | cmp                 dword ptr [ebp - 0x818], esi
            //   7306                 | jae                 8

    condition:
        7 of them and filesize < 524288
}