
rule crime_win_rat_AlienSpy
{
meta:
	description = "Alien Spy Remote Access Trojan"
	author = "General Dynamics Fidelis Cybersecurity Solutions - Threat Research Team"
	reference_1 = "www.fidelissecurity.com/sites/default/files/FTA_1015_Alienspy_FINAL.pdf"
	reference_2 = "www.fidelissecurity.com/sites/default/files/AlienSpy-Configs2_1_2.csv"
	date = "04-Apr-15"
	filetype = "Java"
	hash_1 = "075fa0567d3415fbab3514b8aa64cfcb"
	hash_2 = "818afea3040a887f191ee9d0579ac6ed"
	hash_3 = "973de705f2f01e82c00db92eaa27912c"
	hash_4 = "7f838907f9cc8305544bd0ad4cfd278e"
	hash_5 = "071e12454731161d47a12a8c4b3adfea"
	hash_6 = "a7d50760d49faff3656903c1130fd20b"
	hash_7 = "f399afb901fcdf436a1b2a135da3ee39"
	hash_8 = "3698a3630f80a632c0c7c12e929184fb"
	hash_9 = "fdb674cadfa038ff9d931e376f89f1b6"

   strings:

        $sa_1 = "META-INF/MANIFEST.MF"
        $sa_2 = "Main.classPK"
        $sa_3 = "plugins/Server.classPK"
        $sa_4 = "IDPK"

        $sb_1 = "config.iniPK"
        $sb_2 = "password.iniPK"
        $sb_3 = "plugins/Server.classPK"
        $sb_4 = "LoadStub.classPK"
        $sb_5 = "LoadStubDecrypted.classPK"
        $sb_7 = "LoadPassword.classPK"
        $sb_8 = "DecryptStub.classPK"
        $sb_9 = "ClassLoaders.classPK"

        $sc_1 = "config.xml"
        $sc_2 = "options"
        $sc_3 = "plugins"
        /* $sc_4 = "util" */
        $sc_5 = "util/OSHelper"
        $sc_6 = "Start.class"
        $sc_7 = "AlienSpy"
        /* $sc_8 = "PK" */ /* too short atom - disabled for performance reasons */

  condition:

	uint16(0) == 0x4B50 and filesize < 800KB and ( (all of ($sa_*)) or (all of ($sb_*)) or (all of ($sc_*)) )
}
