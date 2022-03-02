rule win_deathransom_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.deathransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deathransom"
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
        $sequence_0 = { 8bf0 83feff 741d 6a00 8d4508 50 53 }
            // n = 7, score = 100
            //   8bf0                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   741d                 | je                  0x1f
            //   6a00                 | push                0
            //   8d4508               | lea                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   53                   | push                ebx

        $sequence_1 = { 8907 eb59 83fb02 7514 8d45c0 8bd7 50 }
            // n = 7, score = 100
            //   8907                 | mov                 dword ptr [edi], eax
            //   eb59                 | jmp                 0x5b
            //   83fb02               | cmp                 ebx, 2
            //   7514                 | jne                 0x16
            //   8d45c0               | lea                 eax, dword ptr [ebp - 0x40]
            //   8bd7                 | mov                 edx, edi
            //   50                   | push                eax

        $sequence_2 = { 88460b 8a4602 88460a 8a4606 885e07 8b5df0 884e0d }
            // n = 7, score = 100
            //   88460b               | mov                 byte ptr [esi + 0xb], al
            //   8a4602               | mov                 al, byte ptr [esi + 2]
            //   88460a               | mov                 byte ptr [esi + 0xa], al
            //   8a4606               | mov                 al, byte ptr [esi + 6]
            //   885e07               | mov                 byte ptr [esi + 7], bl
            //   8b5df0               | mov                 ebx, dword ptr [ebp - 0x10]
            //   884e0d               | mov                 byte ptr [esi + 0xd], cl

        $sequence_3 = { 8b45f0 8bd8 0b5df4 2345f4 03ca 235dd8 0bd8 }
            // n = 7, score = 100
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8bd8                 | mov                 ebx, eax
            //   0b5df4               | or                  ebx, dword ptr [ebp - 0xc]
            //   2345f4               | and                 eax, dword ptr [ebp - 0xc]
            //   03ca                 | add                 ecx, edx
            //   235dd8               | and                 ebx, dword ptr [ebp - 0x28]
            //   0bd8                 | or                  ebx, eax

        $sequence_4 = { 03cf 0fb7fa 8bc1 894df0 8b55f0 c1e010 8d8e00000100 }
            // n = 7, score = 100
            //   03cf                 | add                 ecx, edi
            //   0fb7fa               | movzx               edi, dx
            //   8bc1                 | mov                 eax, ecx
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   c1e010               | shl                 eax, 0x10
            //   8d8e00000100         | lea                 ecx, dword ptr [esi + 0x10000]

        $sequence_5 = { 6a08 ffd3 50 ff15???????? 8b4de0 8bf0 51 }
            // n = 7, score = 100
            //   6a08                 | push                8
            //   ffd3                 | call                ebx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   8bf0                 | mov                 esi, eax
            //   51                   | push                ecx

        $sequence_6 = { 895da0 8955e8 8955a4 8d0c1a c1c90e 33c8 8b45fc }
            // n = 7, score = 100
            //   895da0               | mov                 dword ptr [ebp - 0x60], ebx
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   8955a4               | mov                 dword ptr [ebp - 0x5c], edx
            //   8d0c1a               | lea                 ecx, dword ptr [edx + ebx]
            //   c1c90e               | ror                 ecx, 0xe
            //   33c8                 | xor                 ecx, eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_7 = { 8b7df8 c1c806 33c8 8bc6 33c7 03ca 2345e8 }
            // n = 7, score = 100
            //   8b7df8               | mov                 edi, dword ptr [ebp - 8]
            //   c1c806               | ror                 eax, 6
            //   33c8                 | xor                 ecx, eax
            //   8bc6                 | mov                 eax, esi
            //   33c7                 | xor                 eax, edi
            //   03ca                 | add                 ecx, edx
            //   2345e8               | and                 eax, dword ptr [ebp - 0x18]

        $sequence_8 = { 8b45fc 8b4004 5f 894304 5e 5b 8be5 }
            // n = 7, score = 100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   5f                   | pop                 edi
            //   894304               | mov                 dword ptr [ebx + 4], eax
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp

        $sequence_9 = { 56 57 8bf9 33f6 8b4708 8b10 85d2 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   8bf9                 | mov                 edi, ecx
            //   33f6                 | xor                 esi, esi
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   85d2                 | test                edx, edx

    condition:
        7 of them and filesize < 133120
}