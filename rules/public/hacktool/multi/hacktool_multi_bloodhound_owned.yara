rule hacktool_multi_bloodhound_owned
{
    meta:
        description = "Bloodhound: Custom queries to document a compromise, find collateral spread of owned nodes, and visualize deltas in privilege gains"
        reference = "https://github.com/porterhau5/BloodHound-Owned/"
        author = "@fusionrace"
    strings:
        $s1 = "Find all owned Domain Admins" fullword ascii wide
        $s2 = "Find Shortest Path from owned node to Domain Admins" fullword ascii wide
        $s3 = "List all directly owned nodes" fullword ascii wide
        $s4 = "Set owned and wave properties for a node" fullword ascii wide
        $s5 = "Find spread of compromise for owned nodes in wave" fullword ascii wide
        $s6 = "Show clusters of password reuse" fullword ascii wide
        $s7 = "Something went wrong when creating SharesPasswordWith relationship" fullword ascii wide
        $s8 = "reference doc of custom Cypher queries for BloodHound" fullword ascii wide
        $s9 = "Created SharesPasswordWith relationship between" fullword ascii wide
        $s10 = "Skipping finding spread of compromise due to" fullword ascii wide
    condition:
        any of them
}
