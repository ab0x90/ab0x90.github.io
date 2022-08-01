
The port scanner can be found at the following location


`https://raw.githubusercontent.com/BornToBeRoot/PowerShell_IPv4NetworkScanner/main/Scripts/IPv4NetworkScan.ps1`

```PowerShell
.\IPv4NetworkScan.ps1 -StartIPv4Address 10.4.23.213 -EndIPv4Address 10.4.23.254
.\IPv4NetworkScan.ps1 -IPv4Address 10.4.23.0 -Mask 255.255.240.0 -DisableDNSResolving
.\IPv4NetworkScan.ps1 -IPv4Address 10.4.23.0 -CIDR 25 -EnableMACResolving
```