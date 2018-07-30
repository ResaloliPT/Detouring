#include <Windows.h>

class Detouring
{
public:
	struct sHook64
	{
		bool isHooked = false;
		void* FunctionAddress = nullptr;
		void* Hook = nullptr;
		char  JmpToHook[14];
		char  JmpFromHook[14];
		char  APIBytes[20];
		void* APIFunction = nullptr;
	};

	struct sHook32
	{
		bool isHooked = false;
		void* FunctionAddress = nullptr;
		void* Hook = nullptr;
		char  JmpToHook[5];
		char  JmpFromHook[5];
		char  APIBytes[20];
		void* APIFunction = nullptr;
	};

	void* DetourFunction64(Detouring::sHook64  &Hook, DWORD_PTR* OrigFunction, DWORD_PTR* HookFunction, const unsigned int ChangedBytes);
	void* DetourFunction32(Detouring::sHook32  &Hook, DWORD_PTR* OrigFunction, DWORD_PTR* HookFunction, const unsigned int ChangedBytes);
private:

};