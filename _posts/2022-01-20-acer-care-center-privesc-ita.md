---
layout: post
title: 🇮🇹 The ace(r) up your sleeve!
subtitle: Vulnerabilità Privilege Escalation nel software Acer Care Center (CVE-2021-45975)
image: /img/acertortellino.jpg
published: true
author:
- last
---
![acer pwnd](/img/acertortellino.jpg)
### TL;DR
Acer installa nella maggior parte dei computer che produce una suite di software chiamata [Care Center Service](https://www.acer.com/ac/en/US/content/software-acer-care-center), la cui versione 4.00.3038 contiene un programma chiamato `ListCheck.exe` che viene eseguito all'avvio con i massimi privilegi consentiti all'utente. Tale eseguibile ha una vulnerabilità di tipo phantom DLL hijacking che può portare a privilege escalation nel caso un amministratore si autentichi sul dispositivo. Alla vulnerabilità è stato assegnato l'identificativo [CVE-2021-45975](https://nvd.nist.gov/vuln/detail/CVE-2021-45975).

### Introduzione
Salve a tutti, è di nuovo [last](https://twitter.com/last0x00) a infastidirvi. Nella mia continua ricerca di disagi esadecimali mi sono imbattuto in un altro software vulnerabile a privilege escalation. Questa volta è stato il turno di [Care Center Service](https://www.acer.com/ac/en/US/content/software-acer-care-center), una suite software che Acer installa nella maggior parte dei dispositivi che vende. Non mi soffermerò su come ho trovato la vulnerabilità in questione, perché il metodo è [letteralmente lo stesso](https://aptw.tf/2021/09/24/armoury-crate-privesc-ita.html) che ho utilizzato per trovare [una vulnerabilità identica in un software prodotto da ASUS](https://nvd.nist.gov/vuln/detail/CVE-2021-40981) lo scorso ottobre.

### La vulnerabilità
Come per quella di ASUS, questa vulnerabilità è un phantom DLL hijacking. Nel momento in cui un utente si autentica su un computer con Acer Care Center installato, uno scheduled task chiamato "Software Update Application" esegue un binario chiamato `ListCheck.exe`. Come configurato nello scheduled task, questo binario viene eseguito ad alta integrità nel caso l'utente appartenga al gruppo degli amministratori locali. Il processo così creato cerca di caricare la libreria `profapi.dll`, andando a cercarla nella cartella `C:\ProgramData\OEM\UpgradeTool\`. 

[![listcheck missing dll]({{site.baseurl}}/img/listcheck_dll.png)]({{site.baseurl}}/img/listcheck_dll.png)

Le ACL della cartella menzionata non sono configurate correttamente (raramente lo sono nel caso di sottocartelle di `C:\ProgramData\`).

[![lax permissions]({{site.baseurl}}/img/listcheck_perm.png)]({{site.baseurl}}/img/listcheck_perm.png)

Ciò significa che, nel caso un utente non privilegiato riesca a posizionare un `profapi.dll` malevolo all'interno della cartella in questione, un utente con privilegi amministrativi finirebbe con il caricare ed eseguire codice malevolo all'interno di un processo ad alta integrità, portando a esecuzione di codice arbitrario locale e a una privilege escalation.

### Patch e workaround
Acer ha rilasciato una patch di sicurezza per Acer Care Center il 27 dicembre 2021. Come workaround preventivo, disabilitare lo scheduled task "Software Update Application" è efficace nel mitigare la vulnerabilità.

### Responsible disclosure timeline (YYYY/MM/DD)
- 2021/10/30: vulnerabilità riportata ad Acer via email a [vulnerability@acer.com](mailto:vulnerability@acer.com);
- 2021/12/08: Acer conferma la ricezione del report e la presenza della vulnerabilità;
- 2021/12/27: Acer rilascia la patch di sicurezza e conferma che il MITRE ha assegnato alla vulnerabilità l'identificativo [CVE-2021-45975](https://nvd.nist.gov/vuln/detail/CVE-2021-45975);
- 2022/01/20: l'advisory relativa alla vulnerabilità e questo post vengono resi pubblici;

Questo è quanto per oggi, alla prossima!
last, out!
