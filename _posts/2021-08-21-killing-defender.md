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

As you can see, SYSTEM (and Administrators) don't have READ/WRITE privilege on the NT symbolic link \SystemRoot (although we can query it and see where it points to), but they have the DELETE privilege. Factor in the fact SYSTEM can create new NT symbolic links and you get yourself the ability to actually change the NT symbolic link: just delete it and recreate it pointing it to something you control. The same applies for other NT symbolic links, \Device\BootDevice included. To actually rewrite this kind of symbolic link we need to use native APIs as there are no Win32 APIs for that. I'll walk you through some code snippets from our project [unDefender](https://github.com/APTortellini/unDefender) which abuses this behaviour. Here's a flowchart of how the different pieces of the software work:

![unDefender flowchart]({{site.baseurl}}/img/undefenderFlowchart.PNG)

First, we setup some data structures that will identify the symlink we want to target and then call the native function NtOpenSymbolicLink to get a handle to said symlink with DELETE privileges.

```C++
UNICODE_STRING symlinkPath;
RtlInitUnicodeString(&symlinkPath, symLinkName.c_str());
OBJECT_ATTRIBUTES symlinkObjAttr{};
InitializeObjectAttributes(&symlinkObjAttr, &symlinkPath, BJ_KERNEL_HANDLE, NULL, NULL);
HANDLE symlinkHandle;

NTSTATUS status = NtOpenSymbolicLinkObject(&symlinkHandle, DELETE, &symlinkObjAttr);
```

After that, we proceed to delete the symlink. To do that we first have to call NtMakeTemporaryObject and pass it the handle to the symlink we got before. That's because this kind of symlinks are created with the OBJ_PERMANENT attribute, which increases the reference counter of the symlink object in the kernel by 1. This means that even if all handles to the symbolic link are closed, the symbolic link will continue to live in the kernel object manager. So, in order to delete it we have to make the object no longer permanent (hence temporary), which means NtMakeTemporaryObject simply decreases the reference counter by one. When we call CloseHandle after that on the handle of the symlink, the reference counter goes to zero and the object is destroyed:

```C++
status = NtMakeTemporaryObject(symlinkHandle);
CloseHandle(symlinkHandle);
```
