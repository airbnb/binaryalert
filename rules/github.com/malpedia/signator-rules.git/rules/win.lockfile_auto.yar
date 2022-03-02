rule win_lockfile_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.lockfile."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lockfile"
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
        $sequence_0 = { e8???????? 488b08 48894db0 8b4008 8945b8 488d056c4d0200 488945c0 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   488b08               | lea                 eax, dword ptr [edx + 5]
            //   48894db0             | dec                 eax
            //   8b4008               | lea                 edx, dword ptr [0x25fc8]
            //   8945b8               | dec                 eax
            //   488d056c4d0200       | lea                 ecx, dword ptr [ebp - 0x30]
            //   488945c0             | test                ebx, ebx

        $sequence_1 = { 488bc8 4c8d442470 488bd7 e8???????? 4885c0 753a 8b442470 }
            // n = 7, score = 200
            //   488bc8               | dec                 eax
            //   4c8d442470           | test                eax, eax
            //   488bd7               | dec                 eax
            //   e8????????           |                     
            //   4885c0               | mov                 dword ptr [ebp - 0x39], esi
            //   753a                 | dec                 eax
            //   8b442470             | mov                 dword ptr [ebp - 0x29], esi

        $sequence_2 = { 4c8bc7 488bd7 488bcb e8???????? 4885f6 75a8 488b5c2450 }
            // n = 7, score = 200
            //   4c8bc7               | dec                 eax
            //   488bd7               | add                 ecx, eax
            //   488bcb               | call                dword ptr [esi]
            //   e8????????           |                     
            //   4885f6               | dec                 eax
            //   75a8                 | mov                 ecx, dword ptr [ebx + 0x18]
            //   488b5c2450           | dec                 eax

        $sequence_3 = { 48898424f0000000 488b442430 4883c010 4889842400010000 b901000000 e8???????? 0fb6c0 }
            // n = 7, score = 200
            //   48898424f0000000     | dec                 esp
            //   488b442430           | mov                 esp, edx
            //   4883c010             | dec                 ecx
            //   4889842400010000     | lea                 ecx, dword ptr [eax + eax]
            //   b901000000           | dec                 ecx
            //   e8????????           |                     
            //   0fb6c0               | cmp                 ecx, eax

        $sequence_4 = { 48ffc2 488b4def 488bc1 4881fa00100000 7215 4883c227 }
            // n = 6, score = 200
            //   48ffc2               | mov                 eax, dword ptr [ecx]
            //   488b4def             | call                dword ptr [eax + 0x98]
            //   488bc1               | dec                 eax
            //   4881fa00100000       | test                eax, eax
            //   7215                 | je                  0x1776
            //   4883c227             | cmp                 byte ptr [esp + 0x30], bl

        $sequence_5 = { 7432 48897c2440 4885c0 7410 4d85c0 740b 498bd6 }
            // n = 7, score = 200
            //   7432                 | dec                 eax
            //   48897c2440           | mul                 dword ptr [esi + 0x18]
            //   4885c0               | dec                 ecx
            //   7410                 | lea                 ecx, dword ptr [eax + eax]
            //   4d85c0               | dec                 ecx
            //   740b                 | mov                 eax, dword ptr [edi + 0x68]
            //   498bd6               | dec                 eax

        $sequence_6 = { 83f901 0f8570010000 448d4108 488d151a600200 e9???????? 41b807000000 }
            // n = 6, score = 200
            //   83f901               | dec                 eax
            //   0f8570010000         | test                eax, eax
            //   448d4108             | je                  0x777
            //   488d151a600200       | dec                 eax
            //   e9????????           |                     
            //   41b807000000         | mov                 edx, dword ptr [ebx + 0x10]

        $sequence_7 = { 3468 8845e2 8b45d0 040f 3465 8845e3 8b45d0 }
            // n = 7, score = 200
            //   3468                 | mov                 edx, dword ptr [ebx + 0x20]
            //   8845e2               | dec                 esp
            //   8b45d0               | mov                 ecx, dword ptr [edi + 0x38]
            //   040f                 | dec                 esp
            //   3465                 | mov                 eax, edx
            //   8845e3               | dec                 eax
            //   8b45d0               | mov                 ecx, dword ptr [ebx + 0x18]

        $sequence_8 = { 4983d700 48f76768 4f8d343c 488bf2 498d0c00 498b4238 493bc8 }
            // n = 7, score = 200
            //   4983d700             | imul                edx, edx, 0xa
            //   48f76768             | dec                 esp
            //   4f8d343c             | mov                 eax, dword ptr [esp + 0x60]
            //   488bf2               | mov                 al, byte ptr [eax + ecx]
            //   498d0c00             | dec                 eax
            //   498b4238             | lea                 eax, dword ptr [ecx + eax*8]
            //   493bc8               | mov                 ecx, 1

        $sequence_9 = { 4903cf 48034de0 48034de8 4803ca 48894838 4883c448 415f }
            // n = 7, score = 200
            //   4903cf               | lea                 ecx, dword ptr [edi + 0x20]
            //   48034de0             | dec                 eax
            //   48034de8             | mov                 eax, dword ptr [esi]
            //   4803ca               | dec                 eax
            //   48894838             | cmp                 dword ptr [ecx], eax
            //   4883c448             | dec                 eax
            //   415f                 | mov                 ebx, eax

    condition:
        7 of them and filesize < 1163264
}