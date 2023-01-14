## ADFS_Windowstransport_Discover
Searching for vulnerable ADFS endpoints that are exposed to the Internet

## About vulnerability
https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/identity/ad-fs/deployment/Best-Practices-Securing-AD-FS.md<br>
https://docs.microsoft.com/ru-ru/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs<br>
https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configure-ad-fs-extranet-smart-lockout-protection<br>
https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configure-ad-fs-extranet-soft-lockout-protection<br>

### URLs
https://**domain.com**/adfs/services/trust/13/windowstransport<br>
https://**domain.com**/ls/idpinitiatedsignon.aspx<br>

### How to disable endpoints:
PS:>Set-AdfsEndpoint -TargetAddressPath /adfs/services/trust/2005/windowstransport -Proxy $false<br>
PS:>Set-AdfsEndpoint -TargetAddressPath /adfs/services/trust/13/windowstransport -Proxy $false<br>

## How to use
Just populate array g_originaldomains with list of domains.
> g_originaldomains = ["google.com"]
