---
layout: post
title: 🇬🇧 The ace(r) up your sleeve!
subtitle: Privilege Escalation vulnerability in Acer Care Center (CVE-2021-45975)
image: /img/acertortellino.jpg
published: true
author:
- last
---
![acer pwnd](/img/acertortellino.jpg)

### TL;DR
Acer ships most of the laptop it sells with a software suite called [Care Center Service](https://www.acer.com/ac/en/US/content/software-acer-care-center) installed. In versions up to 4.00.3038 included, one of the suite's programs is an executable named `ListCheck.exe`, which runs at logon with the highest privilege available and suffers from a phantom DLL hijacking. This can lead to a privilege escalation when an administrator logs in. The vulnerability has been assigned ID [CVE-2021-45975](https://cve.report/CVE-2021-45975)

### Introduction
Greetings mates, [last](https://twitter.com/last0x00) here! As I previously mentioned, lately I've been busy hunting for vulnerabilities and I ended up finding another privilege escalation in one of those softwares computer manufacturers put in the computers they sell. This time it ended up being in [Care Center Service](https://www.acer.com/ac/en/US/content/software-acer-care-center), a software suite Acer uses to keep devices they build updated. I won't delve into the details of how I found the vulnerability, as it's pretty much the same methodology I explained in [the post about a similar vulnerability](https://aptw.tf/2021/09/24/armoury-crate-privesc.html) in an [ASUS product](https://nvd.nist.gov/vuln/detail/CVE-2021-40981) I found last October.

### The vulnerability
As with ASUS' one, this vulnerability is a phantom DLL hijacking. At user logon, a scheduled task named "Software Update Application", created when Acer Care Center is installed, runs a binary named `ListCheck.exe`. As specified in the scheduled task configuration, the binary runs with the highest privileges available to the logged on user (which means high integrity if the user is part of the `BUILTIN\Administrators` group). The process spawned then tries to load `profapi.dll` by first looking into the `C:\ProgramData\OEM\UpgradeTool\` directory. 

[![listcheck missing dll]({{site.baseurl}}/img/listcheck_dll.png)]({{site.baseurl}}/img/listcheck_dll.png)

The ACL of said directory is not properly configured (and often they are not for subfolders of `C:\ProgramData\`), meaning an unprivileged user has write access to it and thus can place there a malicious `profapi.dll` which will be loaded by ListCheck.exe and executed. 

[![lax permissions]({{site.baseurl}}/img/listcheck_perm.png)]({{site.baseurl}}/img/listcheck_perm.png)

This means that, if a privileged user logs on, the malicious `profapi.dll` will be loaded and executed at high integrity, effectively running arbitrary malicious code as an administrator and achieving a privilege escalation.

### Patch and workaround
Acer had released a patch for Acer Care Center on the 27th of December 2021 in order to fix the vulnerability. To prevent the vulnerability from being exploited before the patch is applied, simply disable the "Software Update Application" scheduled task.

### Responsible disclosure timeline (YYYY/MM/DD)
- 2021/10/30: vulnerability reported to Acer via email sent to [vulnerability@acer.com](mailto:vulnerability@acer.com);
- 2021/12/08: Acer acknowledges the report and confirms the vulnerabilty;
- 2021/12/27: Acer releases the patch, MITRE assigns ID [CVE-2021-45975](https://cve.report/CVE-2021-45975) to this vulnerability;
- 2022/01/20: the advisory about the vulnerability and this post are published;

That's all for today folks, see you next time, last out!
