

While PowerUp is used for local priv esc, it can be very userful when trying to obtain local admin privileges on a system


A few useful PowerUp commands


```powershell
. .\PowerUp.ps1

#looks for unquotes services
Get-ServiceUnquoted

#looks for services with weak permissions
Get-ModifiableService

#runs all checks
Invoke-AllChecks

```