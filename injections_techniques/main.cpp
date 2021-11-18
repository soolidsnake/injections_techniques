#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include "techniques.h"

int main(int argc, char **argv)
{
	//ppid_spoofing(atoi(argv[1]));
	//injecting_dll(atoi(argv[1]), argv[2]);
	//apc_injection(atoi(argv[1]), argv[2]);
	//phollowing_injection();
	inject_earlybird();

	return 0;
}