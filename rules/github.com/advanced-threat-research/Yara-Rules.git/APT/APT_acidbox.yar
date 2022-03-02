rule APT_acidbox_kernelmode_module
{
    meta:
    
        description = "Rule to detect the kernel mode component of AcidBox"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-07-24"
        rule_version = "v1"
        malware_type = "kerneldriver"
        malware_family = "Rootkit:W32/Acidbox"
        actor_type = "APT"
        actor_group = "Turla"
        hash1 = "3ef071e0327e7014dd374d96bed023e6c434df6f98cce88a1e7335a667f6749d"
    
    strings:

        $pattern_0 = { 897c2434 8978b8 8d5f28 448bc3 33d2 }
        $pattern_1 = { 4c8d842470010000 488d942418010000 498bcf e8???????? 8bd8 89442460 }
        $pattern_2 = { 4c8bf1 49d1eb 4585c9 0f88a2000000 440fb717 498bd0 }
        $pattern_3 = { ff15???????? 4c8d9c2480000000 498b5b10 498b7318 498b7b20 4d8b7328 498be3 }
        $pattern_4 = { 33d2 41b8???????? 895c2420 e8???????? }
        $pattern_5 = { 895c2420 4885ff 0f8424010000 440f20c0 84c0 0f8518010000 }
        $pattern_6 = { 85f6 0f8469fdffff 488d8424c8010000 41b9???????? }
        $pattern_7 = { 894c2404 750a ffc7 893c24 41ffc3 ebcb 85c9 }
        $pattern_8 = { 488b5c2450 488b742458 488b7c2460 4883c430 }
        $pattern_9 = { 33d2 488b4c2428 e8???????? 448b842450040000 4503c0 4c8d8c2450040000 488bd7 }
   
    condition:

        7 of them and 
        filesize < 78848
}

rule APT_acidbox_main_module_dll
{
    meta:
    
        description = "Rule to detect the Main mode component of AcidBox"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-07-24"
        rule_version = "v1"
        malware_type = "backdoor"
        malware_family = "Backdoor:W32/Acidbox"
        actor_type = "APT"
        actor_group = "Turla"
        hash1 = "eb30a1822bd6f503f8151cb04bfd315a62fa67dbfe1f573e6fcfd74636ecedd5"
    
    strings:

        $pattern_0 = { 7707 b8022d03a0 eb05 e8???????? }
        $pattern_1 = { 4403c8 8bc3 41d1c6 33c6 81c6d6c162ca c1cb02 33c7 }
        $pattern_2 = { e9???????? 412b5c2418 8b45dc 412b442408 41015c241c 410144240c 015f1c }
        $pattern_3 = { 48895c2408 57 4883ec30 488bfa 33db 4885c9 7479 }
        $pattern_4 = { 48895c2408 57 4883ec30 498bd8 488bfa 488364245800 85c9 }
        $pattern_5 = { 488987e0010000 e9???????? 81cb001003a0 e9???????? 488b87a0010000 44847806 742e }
        $pattern_6 = { 4d8bcc 4c8d0596c50100 498bd4 488bce e8???????? 498b9de0010000 c74605aa993355 }
        $pattern_7 = { 4533c0 8d5608 e8???????? 488bf0 4889442460 4885c0 750b }
        $pattern_8 = { 488d5558 41c1ee08 41b802000000 44887559 e8???????? 4c8b4de0 894718 }
        $pattern_9 = { 4d03c2 4d3bc2 4d13cc 4d0303 4d3b03 4d8903 4c8b13 }
   
    condition:

        7 of them and 
        filesize < 550912
}

rule APT_acidbox_ssp_dll_module
{
    meta:
    
        description = "Rule to detect the SSP DLL component of AcidBox"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-07-24"
        rule_version = "v1"
        malware_type = "backdoor"
        malware_family = "Backdoor:W32/Acidbox"
        actor_type = "APT"
        actor_group = "Turla"
        hash1 = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
    
    strings:

        $pattern_0 = { 49897ba0 8bc7 49894398 49897ba8 33c9 49894bb0 }
        $pattern_1 = { 8b8424a8000000 c1e818 88443108 66895c310a 498b0e }
        $pattern_2 = { 8b5f48 413bdd 410f47dd 85db 0f84f1000000 488b4720 4885c0 }
        $pattern_3 = { e8???????? 85c0 78c7 488d9424a0020000 488d8c24e0030000 ff15???????? 4c8bf8 }
        $pattern_4 = { ff15???????? 488bc8 4c8bc6 33d2 ff15???????? 8bfb 895c2420 }
        $pattern_5 = { 415f c3 4c8bdc 49895b10 }
        $pattern_6 = { 488d842488010000 4889442420 41bf???????? 458bcf 4c8bc7 418bd7 488d8c2490000000 }
        $pattern_7 = { c1e908 0fb6c9 3bce 77b6 8bd0 b9???????? c1ea10 }
        $pattern_8 = { 4c8bc3 ba???????? 488d4c2438 e8???????? 89442430 85c0 7508 }
        $pattern_9 = { bb02160480 8bc3 488b5c2440 488b742448 488b7c2450 4883c430 }
   
    condition:

        7 of them and 
        filesize < 199680
}