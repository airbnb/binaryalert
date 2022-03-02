rule win_gsecdump_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.gsecdump."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gsecdump"
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
        $sequence_0 = { 8b5c2458 89742414 3bc1 89442420 0f8402010000 }
            // n = 5, score = 100
            //   8b5c2458             | mov                 ebx, dword ptr [esp + 0x58]
            //   89742414             | mov                 dword ptr [esp + 0x14], esi
            //   3bc1                 | cmp                 eax, ecx
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   0f8402010000         | je                  0x108

        $sequence_1 = { 51 2bd8 53 8bce 8945a4 e8???????? 894608 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   2bd8                 | sub                 ebx, eax
            //   53                   | push                ebx
            //   8bce                 | mov                 ecx, esi
            //   8945a4               | mov                 dword ptr [ebp - 0x5c], eax
            //   e8????????           |                     
            //   894608               | mov                 dword ptr [esi + 8], eax

        $sequence_2 = { 7404 c6450b01 f6c310 7425 83e3ef 397dec 895d04 }
            // n = 7, score = 100
            //   7404                 | je                  6
            //   c6450b01             | mov                 byte ptr [ebp + 0xb], 1
            //   f6c310               | test                bl, 0x10
            //   7425                 | je                  0x27
            //   83e3ef               | and                 ebx, 0xffffffef
            //   397dec               | cmp                 dword ptr [ebp - 0x14], edi
            //   895d04               | mov                 dword ptr [ebp + 4], ebx

        $sequence_3 = { 8b4b08 8b542420 83c40c 50 51 52 8bce }
            // n = 7, score = 100
            //   8b4b08               | mov                 ecx, dword ptr [ebx + 8]
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]
            //   83c40c               | add                 esp, 0xc
            //   50                   | push                eax
            //   51                   | push                ecx
            //   52                   | push                edx
            //   8bce                 | mov                 ecx, esi

        $sequence_4 = { 8bc1 83fe08 89442414 7202 8b09 8b5214 8d3451 }
            // n = 7, score = 100
            //   8bc1                 | mov                 eax, ecx
            //   83fe08               | cmp                 esi, 8
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   7202                 | jb                  4
            //   8b09                 | mov                 ecx, dword ptr [ecx]
            //   8b5214               | mov                 edx, dword ptr [edx + 0x14]
            //   8d3451               | lea                 esi, dword ptr [ecx + edx*2]

        $sequence_5 = { 89742444 896c2448 e8???????? 8b08 83f9fe 8b7804 7414 }
            // n = 7, score = 100
            //   89742444             | mov                 dword ptr [esp + 0x44], esi
            //   896c2448             | mov                 dword ptr [esp + 0x48], ebp
            //   e8????????           |                     
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   83f9fe               | cmp                 ecx, -2
            //   8b7804               | mov                 edi, dword ptr [eax + 4]
            //   7414                 | je                  0x16

        $sequence_6 = { eb02 8bc1 83fe08 89442414 7202 8b09 8b5214 }
            // n = 7, score = 100
            //   eb02                 | jmp                 4
            //   8bc1                 | mov                 eax, ecx
            //   83fe08               | cmp                 esi, 8
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   7202                 | jb                  4
            //   8b09                 | mov                 ecx, dword ptr [ecx]
            //   8b5214               | mov                 edx, dword ptr [edx + 0x14]

        $sequence_7 = { 50 8d442434 64a300000000 8be9 8b5c2448 8b4304 33ff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d442434             | lea                 eax, dword ptr [esp + 0x34]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8be9                 | mov                 ebp, ecx
            //   8b5c2448             | mov                 ebx, dword ptr [esp + 0x48]
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   33ff                 | xor                 edi, edi

        $sequence_8 = { 89442404 7578 8b442414 8b4814 8b5018 53 55 }
            // n = 7, score = 100
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   7578                 | jne                 0x7a
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   8b4814               | mov                 ecx, dword ptr [eax + 0x14]
            //   8b5018               | mov                 edx, dword ptr [eax + 0x18]
            //   53                   | push                ebx
            //   55                   | push                ebp

        $sequence_9 = { 6a02 8d4c2414 e8???????? 8d4c2410 c605????????01 e8???????? 83fd03 }
            // n = 7, score = 100
            //   6a02                 | push                2
            //   8d4c2414             | lea                 ecx, dword ptr [esp + 0x14]
            //   e8????????           |                     
            //   8d4c2410             | lea                 ecx, dword ptr [esp + 0x10]
            //   c605????????01       |                     
            //   e8????????           |                     
            //   83fd03               | cmp                 ebp, 3

    condition:
        7 of them and filesize < 630784
}