#include "Detouring.h"

//Detours Original Function to our code then to an Patch then original code (Trampoline) x64 Edition
void* Detouring::DetourFunction64(Detouring::sHook64  &Hook, DWORD_PTR* OrigFunction, DWORD_PTR* HookFunction, const unsigned int ChangedBytes){
	DWORD origProtection; // Store Original Protection
	BYTE stub[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };// x64 jmp stub

	if (ChangedBytes < sizeof(stub))
		return NULL; // const unsigned int ChangedBytes MUST be bigger than the size of stub

	if (Hook.isHooked) // Check if Already Hooked
		return false;

	/*============  Prepare Hook Struct ================*/
	memcpy(Hook.JmpToHook, stub, sizeof(Hook.JmpToHook)); // Copy Stub to our hook struct
	memcpy(Hook.JmpFromHook, stub, sizeof(Hook.JmpFromHook)); // Copy Stub to our hook struct
	Hook.FunctionAddress = OrigFunction; // Copy Original Function Address to Hook Struct
	Hook.Hook = HookFunction; // Copy Hook Function Address to Hook Struct
	Hook.APIFunction = VirtualAlloc(NULL, sizeof(Hook.JmpFromHook) + ChangedBytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate Space for original bytes (Patch)
	for (int i = 0; i < sizeof(Hook.APIBytes); i++)
		Hook.APIBytes[i] = 0x90; // Set all APIbytes to NOP (as we can store up to 20 bytes some might not be needed) even though theres a jump at least keeps "code clean"
	memcpy(Hook.APIBytes, Hook.FunctionAddress, ChangedBytes); // Copy original OPCodes to Struct

	/*============  From original to Hook ================*/
	memcpy(Hook.JmpToHook + 6, &Hook.Hook, 8); // Store Original function address offseted to struct

	VirtualProtect(Hook.FunctionAddress, ChangedBytes, PAGE_EXECUTE_READWRITE, &origProtection); // Change Protection to READ/WRITE
	memcpy(Hook.FunctionAddress, Hook.JmpToHook, ChangedBytes); // Edit Original bytes to redirect to our Hook
	for (int i = sizeof(Hook.JmpToHook); i < ChangedBytes; i++)
		*(BYTE*)((DWORD_PTR)Hook.FunctionAddress + i) = 0x90; // Set extra bytes (above the sub size) to NOP
	VirtualProtect(Hook.FunctionAddress, ChangedBytes, origProtection, &origProtection); // Restore Original Protection

	/*============  From Hook to Original ================*/
	void *pOffset1 = Hook.FunctionAddress; // Make copy of Original function address
	pOffset1 = static_cast<char*>(pOffset1)+(ChangedBytes); // Add offset to Original function address

	memcpy(Hook.JmpFromHook + 6, &pOffset1, 8); // Store Original function address offseted to struct

	memcpy((void*)((DWORD_PTR)Hook.APIFunction), Hook.APIBytes, ChangedBytes); // Copy Original Bytes to our Trampoline
	memcpy((void*)((DWORD_PTR)Hook.APIFunction + ChangedBytes), Hook.JmpFromHook, sizeof(Hook.JmpFromHook)); // Add jmp to Original Code

	return Hook.APIFunction; // Return where Original code Starts (at our trampoline) usefull to call the original code direcly instead of calling our code where not needed
}



//Detours Original Function to our code then to an Patch then original code (Trampoline)
void* Detouring::DetourFunction32(Detouring::sHook32  &Hook, DWORD* OrigFunction, DWORD* HookFunction, const unsigned int ChangedBytes){
	DWORD origProtection; // Store Original Protection
	BYTE stub[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };// x32 jmp stub

	if (ChangedBytes < sizeof(stub))
		return NULL; // const unsigned int ChangedBytes MUST be bigger than the size of stub

	if (Hook.isHooked) // Check if Already Hooked
		return false;

	/*============  Prepare Hook Struct ================*/
	memcpy(Hook.JmpToHook, stub, sizeof(Hook.JmpToHook)); // Copy Stub to our hook struct
	memcpy(Hook.JmpFromHook, stub, sizeof(Hook.JmpFromHook)); // Copy Stub to our hook struct
	Hook.FunctionAddress = OrigFunction; // Copy Original Function Address to Hook Struct
	Hook.Hook = HookFunction; // Copy Hook Function Address to Hook Struct
	Hook.APIFunction = VirtualAlloc(NULL, sizeof(Hook.JmpFromHook) + ChangedBytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate Space for original bytes (Patch)
	for (int i = 0; i < sizeof(Hook.APIBytes); i++)
		Hook.APIBytes[i] = 0x90; // Set all APIbytes to NOP (as we can store up to 20 bytes some might not be needed) even though theres a jump at least keeps "code clean"
	memcpy(Hook.APIBytes, Hook.FunctionAddress, ChangedBytes); // Copy original OPCodes to Struct

	/*============  From original to Hook ================*/
	*(PULONG)&Hook.JmpToHook[1] = (ULONG)Hook.Hook - (ULONG)Hook.FunctionAddress - 5; // Store Jump address to struct

	VirtualProtect(Hook.FunctionAddress, ChangedBytes, PAGE_EXECUTE_READWRITE, &origProtection); // Change Protection to READ/WRITE
	memcpy(Hook.FunctionAddress, Hook.JmpToHook, ChangedBytes); // Edit Original bytes to redirect to our Hook
	for (int i = sizeof(Hook.JmpToHook); i < ChangedBytes; i++)
		*(BYTE*)((DWORD_PTR)Hook.FunctionAddress + i) = 0x90; // Set extra bytes (above the sub size) to NOP
	VirtualProtect(Hook.FunctionAddress, ChangedBytes, origProtection, &origProtection); // Restore Original Protection

	/*============  From Hook to Original ================*/
	ULONG tempOrigF, tempNewF;
	tempOrigF = (ULONG)Hook.APIFunction + 5;
	tempNewF = (ULONG)Hook.FunctionAddress + 5;

	void *pOffset = Hook.APIFunction; // Make copy of Trampoline function address
	pOffset = static_cast<char*>(pOffset)+(ChangedBytes); // Add offset to end of function

	memcpy((void*)((DWORD_PTR)Hook.APIFunction), Hook.APIBytes, ChangedBytes); // Copy Original Bytes to our Trampoline
	*(LPBYTE)((LPBYTE)Hook.APIFunction + ChangedBytes) = 0xE9; // Add jmp opcode to the end of patch code
	*(PULONG)((LPBYTE)Hook.APIFunction + ChangedBytes + 1) = (ULONG)tempNewF - (ULONG)tempOrigF - 5; // Add jmp to Original Code

	memcpy(Hook.JmpFromHook, pOffset, 5); // Store Original function address offseted to struct

	return Hook.APIFunction; // Return where Original code Starts (at our trampoline) usefull to call the original code direcly instead of calling our code where not needed
}