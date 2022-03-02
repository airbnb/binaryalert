rule APT_UNC2452_Webshell_Chopper_Mar_2021_1 {
   meta:
      description = "Detect exploit listener in the exchange configuration for Webshell Chopper used by UNC2452 group"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2021-03-07"
   strings:
      // check exploit listeners (C# and JS)

      // C# listener version
      $l1 = { 20 68 74 74 70 3a 2f 2f ?? 2f 3c 73 63 72 69 70 74 20 4c 61 6e 67 75 61 67 65 3d 22 63 23 22 20 72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 3e 76 6f 69 64 20 50 61 67 65 5f 4c 6f 61 64 28 6f 62 6a 65 63 74 20 73 65 6e 64 65 72 2c 20 45 76 65 6e 74 41 72 67 73 20 65 29 7b 69 66 20 28 52 65 71 75 65 73 74 2e 46 69 6c 65 73 2e 43 6f 75 6e 74 21 3d 30 29 20 7b 20 52 65 71 75 65 73 74 2e 46 69 6c 65 73 5b 30 5d 2e 53 61 76 65 41 73 28 53 65 72 76 65 72 2e 4d 61 70 50 61 74 68 28 22 [5-14] 22 29 29 3b 7d 7d 3c 2f 73 63 72 69 70 74 3e }
      //  http://#/<script Language="c#" runat="server">void Page_Load(object sender, EventArgs e){if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath("#"));}}</script>
      
      // JS listener version 
      $l2 = { 68 74 74 70 3a 2f 2f ?? 2f 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 4a 53 63 72 69 70 74 22 20 72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 3e 66 75 6e 63 74 69 6f 6e 20 50 61 67 65 5f 4c 6f 61 64 28 29 7b 65 76 61 6c 28 [-] 2c 22 75 6e 73 61 66 65 22 29 3b 7d 3c 2f 73 63 72 69 70 74 3e }
      // http://#/script language="JScript" runat="server">function Page_Load(){eval(#,"unsafe");}</script>

      // Check if this in the configuration file (avoid false positive)
      $c1 = { 5c 4f 41 42 20 28 44 65 66 61 75 6c 74 20 57 65 62 20 53 69 74 65 29 } // \OAB (Default Web Site)
      $c2 = "ExternalUrl" fullword ascii // RemoteURL for the listener
      $c3 = { 49 49 53 3a 2f 2f [10-30] 2f 57 33 53 56 43 2f [1-3] 2f 52 4f 4f 54 2f 4f 41 42 } // IIS://#/W3SVC/#/ROOT/OAB
      $c4 = "FrontEnd\\HttpProxy\\OAB" fullword ascii
      $c5 = "/Configuration/Schema/ms-Exch-OAB-Virtual-Directory" fullword ascii
   condition:
      filesize > 1KB and 1 of ($l*) and 3 of ($c*) 
}
