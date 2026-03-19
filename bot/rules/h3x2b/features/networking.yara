import "pe"

//Detect capabilities of opening network sockets

rule winsocks : feature networking windows
{
meta:
	description = "Imports Winsock Library"

condition:
	// MZ at the beginning of file
        uint16be(0) == 0x4d5a and

	pe.imports("wsock32.dll","WSAStartup") and
	pe.imports("wsock32.dll","socket")
}




