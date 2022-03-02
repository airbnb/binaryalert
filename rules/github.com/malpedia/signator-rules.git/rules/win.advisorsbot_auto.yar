rule win_advisorsbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.advisorsbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.advisorsbot"
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
        $sequence_0 = { 8bc1 2bc2 d1e8 03c2 c1e808 }
            // n = 5, score = 1000
            //   8bc1                 | mov                 eax, ecx
            //   2bc2                 | sub                 eax, edx
            //   d1e8                 | shr                 eax, 1
            //   03c2                 | add                 eax, edx
            //   c1e808               | shr                 eax, 8

        $sequence_1 = { 8bc2 33d2 c1e809 f7f1 }
            // n = 4, score = 800
            //   8bc2                 | mov                 eax, edx
            //   33d2                 | xor                 edx, edx
            //   c1e809               | shr                 eax, 9
            //   f7f1                 | div                 ecx

        $sequence_2 = { 8bc2 33d2 c1e808 f7f1 }
            // n = 4, score = 800
            //   8bc2                 | mov                 eax, edx
            //   33d2                 | xor                 edx, edx
            //   c1e808               | shr                 eax, 8
            //   f7f1                 | div                 ecx

        $sequence_3 = { b89b01a311 f7e1 2bca d1e9 03ca }
            // n = 5, score = 800
            //   b89b01a311           | mov                 eax, 0x11a3019b
            //   f7e1                 | mul                 ecx
            //   2bca                 | sub                 ecx, edx
            //   d1e9                 | shr                 ecx, 1
            //   03ca                 | add                 ecx, edx

        $sequence_4 = { d1e8 03c2 33d2 c1e809 }
            // n = 4, score = 700
            //   d1e8                 | shr                 eax, 1
            //   03c2                 | add                 eax, edx
            //   33d2                 | xor                 edx, edx
            //   c1e809               | shr                 eax, 9

        $sequence_5 = { b80923ed58 f7e1 8bc1 2bc2 }
            // n = 4, score = 700
            //   b80923ed58           | mov                 eax, 0x58ed2309
            //   f7e1                 | mul                 ecx
            //   8bc1                 | mov                 eax, ecx
            //   2bc2                 | sub                 eax, edx

        $sequence_6 = { 8bc2 c1e809 33d2 f7f1 }
            // n = 4, score = 700
            //   8bc2                 | mul                 ecx
            //   c1e809               | sub                 ecx, edx
            //   33d2                 | shr                 ecx, 1
            //   f7f1                 | add                 ecx, edx

        $sequence_7 = { 0fb7842480000000 0fb78c2480000000 33d2 f7f1 }
            // n = 4, score = 600
            //   0fb7842480000000     | inc                 ecx
            //   0fb78c2480000000     | mul                 eax
            //   33d2                 | sub                 ecx, edx
            //   f7f1                 | shr                 ecx, 1

        $sequence_8 = { d1e9 03ca c1e907 23c8 }
            // n = 4, score = 600
            //   d1e9                 | mov                 eax, 0x11a3019b
            //   03ca                 | mul                 ecx
            //   c1e907               | sub                 ecx, edx
            //   23c8                 | shr                 ecx, 1

        $sequence_9 = { 8b442408 8b4c2408 33d2 f7f1 }
            // n = 4, score = 600
            //   8b442408             | shr                 ecx, 1
            //   8b4c2408             | add                 ecx, edx
            //   33d2                 | mov                 eax, 0x90d4f121
            //   f7f1                 | mul                 ecx

        $sequence_10 = { 8b442424 8b4c2424 33d2 f7f1 }
            // n = 4, score = 600
            //   8b442424             | add                 ecx, edx
            //   8b4c2424             | shr                 ecx, 7
            //   33d2                 | and                 ecx, eax
            //   f7f1                 | mul                 ecx

        $sequence_11 = { 418bc8 41f7e0 2bca d1e9 }
            // n = 4, score = 600
            //   418bc8               | shr                 ecx, 1
            //   41f7e0               | add                 ecx, edx
            //   2bca                 | inc                 ecx
            //   d1e9                 | mov                 ecx, eax

        $sequence_12 = { 0fb6c1 0fb6ca 33d2 f7f1 }
            // n = 4, score = 500
            //   0fb6c1               | shr                 ecx, 1
            //   0fb6ca               | add                 ecx, edx
            //   33d2                 | shr                 ecx, 8
            //   f7f1                 | mov                 eax, 0x38d22d37

        $sequence_13 = { 5e 5d 0fb7c1 5b }
            // n = 4, score = 500
            //   5e                   | xor                 edx, edx
            //   5d                   | div                 ecx
            //   0fb7c1               | mov                 ax, word ptr [esp + 0x10]
            //   5b                   | pop                 edi

        $sequence_14 = { 5f 5e 5d 0fb7c2 }
            // n = 4, score = 500
            //   5f                   | mul                 ecx
            //   5e                   | sub                 ecx, edx
            //   5d                   | shr                 ecx, 1
            //   0fb7c2               | add                 ecx, edx

        $sequence_15 = { 0fb7c0 0fb7c9 33d2 f7f1 }
            // n = 4, score = 500
            //   0fb7c0               | movzx               eax, cl
            //   0fb7c9               | movzx               ecx, dl
            //   33d2                 | xor                 edx, edx
            //   f7f1                 | div                 ecx

        $sequence_16 = { 0fb7c1 0fb7ca 33d2 f7f1 }
            // n = 4, score = 500
            //   0fb7c1               | pop                 esi
            //   0fb7ca               | pop                 ebp
            //   33d2                 | movzx               eax, cx
            //   f7f1                 | pop                 ebx

    condition:
        7 of them and filesize < 434176
}