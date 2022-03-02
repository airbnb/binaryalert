rule VMProtectStub
{
    meta:
        id = "2mnOM2GhTL6NcFzr8Jt2RS"
        fingerprint = "60278c38aaf4a92a81cdda628e85dc2670f1e95665fcfbac87f40b225a4a28c2"
        version = "1.0"
        creation_date = "2020-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies VMProtect packer stub."
        category = "MALWARE"

    strings:
        $ = ".?AV?$VirtualAllocationManager@VRealAllocationStrategy@@@@" ascii wide
        $ = ".?AVEncryptedFastDllStream@@" ascii wide
        $ = ".?AVGetBlock_CC@HardwareID@@" ascii wide
        $ = ".?AVHookManager@@" ascii wide
        $ = ".?AVIDllStream@@" ascii wide
        $ = ".?AVIGetBlock@HardwareID@@" ascii wide
        $ = ".?AVIHookManager@@" ascii wide
        $ = ".?AVIUrlBuilderSource@@" ascii wide
        $ = ".?AVIVirtualAllocationManager@@" ascii wide
        $ = ".?AVMyActivationSource@@" ascii wide

    condition:
        2 of them
}