---
layout: post
title: Stealing weapons from the Armoury	
subtitle: Root cause analysis of a privilege escalation vulnerability in ASUS ROG Armoury Crate Lite Service v4.2.8
image: /img/armourytortellino.jpg
published: true
author:
- last
---
![armoury pwnd](/img/armourytortellino.jpg)
### TL;DR
[ASUS ROG Armoury Crate](https://rog.asus.com/us/armoury-crate/) ships with a service called Armoury Crate Lite Service which suffers from a phantom DLL hijacking vulnerability that allows a low privilege user to execute code in the context other users, administrators included. To trigger the vulnerability, an administrator must log in after the attacker has placed the malicious DLL at the path `C:\ProgramData\ASUS\GamingCenterLib\.DLL`. The issue has been fixed with the release of Armoury Crate Lite Service 4.2.10.

### Introduction
Greetings fellow hackers, last here! Recently I've been looking for vulnerabilities here and there - too much free time maybe? Specifically, I focused on hunting for DLL hijackings in privileged processes, as they usually lead to a local privilege escalation. A DLL hijacking revolves around forcing a process to run an attacker controlled DLL instead of the legitimate DLL the process is trying to load, nothing more. To make a process load your DLL you have to control the path from which said DLL is loaded. There are essentially two kinds of DLL hijackings: standard DLL hijackings and phantom DLL hijackings. The main difference is that in standard ones the legitimate DLL exists and is overwritten or proxied by the attacker's DLL, while in phantom DLL hijackings the process tries to load a non existing DLL, hence the attacker can just drop its malicious DLL in the path and call it a day.

By messing up with [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) I ended up finding a phantom DLL hijacking in [ASUS ROG Armoury Crate](https://rog.asus.com/us/armoury-crate/), a software commonly installed in gaming PCs with a TUF/ROG motherboard to manage LEDs and fans.

![such gaming much 0days gif](/img/armourycratememe.gif)

Last year I assembled a PC with an ASUS TUF motherboard, so I have this software installed. This kind of software is usually poorly designed from a security perspective - not shaming ASUS here, it's just a matter of fact as gaming software is usually not designed with security in mind, it has to be flashy and eye-catching - so I ended up focusing my effort on this particular piece of software.

At login time, Armoury Crate's own service, called Armoury Crate Lite Service, spawns a number of processes, the ones that caught my eyes though were `ArmouryCrate.Service.exe` and its child `ArmouryCrate.UserSessionHelper.exe`. As you can see in the next screenshot, the first runs as SYSTEM as it's the process of the service itself, while the second runs at High integrity (i.e. elevated) if the current user is an administrator, or Medium integrity if the user is a low privilege one. Keep this in mind, we will come back to it later.

![armourycrate arch](/img/armouryservice0.png)

### It's hunting season
Now that we have laid down our targets, let's look at how we are going to approach the research. The methodology we will use is the following:
1. Look for `CreateFile` operations failing with a "NO SUCH FILE" or "PATH NOT FOUND" code;
2. Inspect the operation to make sure it happens as a result of a call to a LoadLibrary-like function. CreateFile-like calls in Windows are not used only to create new files, but also to open existing ones;
3. Make sure we can write to - or create the - path from which the DLL is loaded;
4. Profit!

Hunting for this type of vulnerabilities is actually fairly easy and requires little effort. As I have explained in [this Twitter thread](https://twitter.com/last0x00/status/1435160730035183616), you just have to fire up Process Monitor with admin privileges, set some filters and then investigate the results. Let's start from the filters: since we are focusing on phantom DLL hijackings, we want to see all the __privileged__ processes failing to load a DLL with an error like "PATH NOT FOUND" or "NO SUCH FILE". To do so go to the menu bar, `Filter->Filter...` and add the following filters:
- Operation - is - CreateFile - Include
- Result - contains - not found - Include
- Result - contains - no such - Include
- Path - ends with - .dll - Include
- Integrity - is - System - Include
- Integrity - is - High - Include

![procmon filters](/img/procmonfilter0.png)

Once you have done that, go back to the menu bar, then `Filter->Save Filter...` so that we can load it later. As a lot SYSTEM and High integrity processes run as a result of a service running we now want to log the boot process of the computer and analyze it with Process Monitor. In order to do so head to the menu bar, then `Options->Enable Boot Logging`, leave everything as default and restart the computer. After logging back in, open Process Monitor once again, save the `Bootlog.pml` file and wait for Process Monitor to parse it. Once it's finished doing its things, load the filter we prepared previously by clicking on `Filter->Load Filter`. Now we should see only potential phantom hijackings. 

![armoury missing DLL](/img/armourymissingdll.png)

In Armoury Crate's case, you can see it tries to load `C:\ProgramData\ASUS\GamingCenterLib\.DLL` which is an interesting path because ACLs are not set automatically in subfolders of `C:\ProgramData\`, a thing that happens instead for subfolders of `C:\Program Files\`. This means there's a high probability `C:\ProgramData\` subfolders will be writable by unprivileged users.

To make sure the `CreateFile` operation we are looking at happens as a result of a LoadLibrary-like function we can open the event and navigate to the `Stack` tab to check the sequence of function calls which lead to the `CreateFile` operation. As you can see from the following screenshot, this is exactly the case as we have a call to `LoadLibraryExW`:

![armoury crate loadlibrary](/img/loadlibrary.png)

To inspect the ACL of the folder from which Armoury Crate tries to load the DLL we can use Powershell's `Get-Acl` cmdlet this way:
```
Get-Acl 'C:\ProgramData\ASUS\GamingCenterLib' | Select-Object *
```

This command will return the following output, which tells us `BUILTIN\Users` users have write access to the directory:

![armoury acls](/img/acl0.png)

A more user friendly way of showing the effective access a user has on a particular resource is to open its properties, navigate to the `Security` tab, click on `Advanced`, switch to the `Effective Access` tab, select a user and then click on `View effective access`. The result of this operation is the effective access a user has to said resource, considering also the permissions it inherits from the groups he is part of.

![armoury acls gui](/img/acl.png)

Alright, now that we know we can write to `C:\ProgramData\ASUS\GamingCenterLib` we just have to compile a DLL named `.DLL` and drop it there. We will go with a simple DLL which will add a user:
```c++
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  
    DWORD fdwReason,     
    LPVOID lpReserved ) 
{
    system("cmd /c \"net user last last /add\"");
    return true;
}
```

Now that we have everything ready we just have to wait for a privileged user to log in. This is needed as the DLL is loaded by `ArmouryCrate.UserSessionHelper.exe` which runs with the highest privileges available to the user to which the session belongs. As you can see in the following demo, as soon as the privileged user logs in, we have a new user, confirming administrator-level code execution.

### Root cause analysis
Let's now have a look at what caused this vulnerability. As you can see from the call stack shown in the screenshot in the beginning of this article, the DLL is loaded from code located inside `GamingCenterPlugin.dll`, at offset `QueryLibrary + 0x167d` which is actually another function I renamed `DllLoadLibraryImplement` (by reversing `GamingCenterPlugin.dll` with IDA Pro you can see most functions in this DLL have some sort of logging feature which references strings containing the possible name of the function). Here's the code responsible for the call to `LoadLibraryExW`:

![ida call](/img/idaloadlibrary.png)

We have two culprits here:
1. A DLL is loaded without any check. ASUS fixed this by implementing a cryptographic check on the DLLs loaded by this process to make sure they are signed by ASUS themselves;
2. The ACL of `C:\ProgramData\ASUS\GamingCenterLib\` are not properly set. ASUS has __NOT__ fixed this, which means that, in the case a bypass is found for reason 1, the software would be vulnerable again as `ArmouryCrate.UserSessionHelper.exe` now looks for DLLs in that folder with a 6-character-long name (by searching them with the wildcard `??????.DLL` as you can see with Procmon). If you use Armoury Crate I suggest hand-fixing the ACL of `C:\ProgramData\ASUS\GamingCenterLib\` in order to give access to the whole directory tree only to members of the Administrators group.

### Responsible disclosure timeline (YYYY/MM/DD)
- 2021/09/06: vulnerability reported to ASUS via their web portal;
- 2021/09/10: ASUS acknowledges the report and forwards it to their dev branch;
- 2021/09/13: ASUS devs confirm the vulnerability and say it will be fixed in the next release, expected for week 39 of this year (27/09 - 01/10);
- 2021/09/24: ASUS confirms the vulnerability has been fixed in version 4.2.10 of the service;

Kudos to ASUS for the quick response and professionalism in dealing with the problem! That's all for today lads, last out!
