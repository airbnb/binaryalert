rule win_webc2_bolid_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.webc2_bolid."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_bolid"
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
        $sequence_0 = { bf???????? 83c9ff 33c0 8b9424bc000000 }
            // n = 4, score = 100
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   8b9424bc000000       | mov                 edx, dword ptr [esp + 0xbc]

        $sequence_1 = { 51 e8???????? 83c404 8b842480000000 895c2470 3bc3 895c2474 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b842480000000       | mov                 eax, dword ptr [esp + 0x80]
            //   895c2470             | mov                 dword ptr [esp + 0x70], ebx
            //   3bc3                 | cmp                 eax, ebx
            //   895c2474             | mov                 dword ptr [esp + 0x74], ebx

        $sequence_2 = { eb09 51 e8???????? 83c404 8b855cffffff }
            // n = 5, score = 100
            //   eb09                 | jmp                 0xb
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b855cffffff         | mov                 eax, dword ptr [ebp - 0xa4]

        $sequence_3 = { 8b4d0c 51 e8???????? 8bf8 83c404 85ff 897dec }
            // n = 7, score = 100
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c404               | add                 esp, 4
            //   85ff                 | test                edi, edi
            //   897dec               | mov                 dword ptr [ebp - 0x14], edi

        $sequence_4 = { 8b83b0000000 85c0 7505 b8???????? 8b5344 03c9 51 }
            // n = 7, score = 100
            //   8b83b0000000         | mov                 eax, dword ptr [ebx + 0xb0]
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   b8????????           |                     
            //   8b5344               | mov                 edx, dword ptr [ebx + 0x44]
            //   03c9                 | add                 ecx, ecx
            //   51                   | push                ecx

        $sequence_5 = { e8???????? c644245405 bf???????? 83cdff 33c0 8bcd }
            // n = 6, score = 100
            //   e8????????           |                     
            //   c644245405           | mov                 byte ptr [esp + 0x54], 5
            //   bf????????           |                     
            //   83cdff               | or                  ebp, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   8bcd                 | mov                 ecx, ebp

        $sequence_6 = { 8b0485c01f4100 03c6 8a5004 f6c201 0f849e010000 }
            // n = 5, score = 100
            //   8b0485c01f4100       | mov                 eax, dword ptr [eax*4 + 0x411fc0]
            //   03c6                 | add                 eax, esi
            //   8a5004               | mov                 dl, byte ptr [eax + 4]
            //   f6c201               | test                dl, 1
            //   0f849e010000         | je                  0x1a4

        $sequence_7 = { f3a4 8b8bd0000000 8b75e4 8983d4000000 03c1 c60000 8d450c }
            // n = 7, score = 100
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b8bd0000000         | mov                 ecx, dword ptr [ebx + 0xd0]
            //   8b75e4               | mov                 esi, dword ptr [ebp - 0x1c]
            //   8983d4000000         | mov                 dword ptr [ebx + 0xd4], eax
            //   03c1                 | add                 eax, ecx
            //   c60000               | mov                 byte ptr [eax], 0
            //   8d450c               | lea                 eax, dword ptr [ebp + 0xc]

        $sequence_8 = { 68???????? 8d4c2438 e8???????? 8a442430 83ec10 8bf4 }
            // n = 6, score = 100
            //   68????????           |                     
            //   8d4c2438             | lea                 ecx, dword ptr [esp + 0x38]
            //   e8????????           |                     
            //   8a442430             | mov                 al, byte ptr [esp + 0x30]
            //   83ec10               | sub                 esp, 0x10
            //   8bf4                 | mov                 esi, esp

        $sequence_9 = { c7851cffffff01010000 ff15???????? 8a4d1b 53 884d88 8d4d88 8bf0 }
            // n = 7, score = 100
            //   c7851cffffff01010000     | mov    dword ptr [ebp - 0xe4], 0x101
            //   ff15????????         |                     
            //   8a4d1b               | mov                 cl, byte ptr [ebp + 0x1b]
            //   53                   | push                ebx
            //   884d88               | mov                 byte ptr [ebp - 0x78], cl
            //   8d4d88               | lea                 ecx, dword ptr [ebp - 0x78]
            //   8bf0                 | mov                 esi, eax

    condition:
        7 of them and filesize < 163840
}