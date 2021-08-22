---
layout: post
title: The dying knight in the shiny armour
subtitle: Killing Defender through NT symbolic links redirection while keeping it unbothered
author:
- last
---
### TL;DR
With Administrator level privileges and without interacting with the GUI, it's possible to prevent Defender from doing its job while keeping it alive and without disabling tamper protection by redirecting the \Device\BootDevice NT symbolic link which is part of the NT path from where Defender's WdFilter driver binary is loaded. This can also be used to make Defender load an arbitrary driver, which no tool succeeds in locating.
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
