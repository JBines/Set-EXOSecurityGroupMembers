# Set-EXOSecurityGroupMembers
```powershell
<# 
.SYNOPSIS
This script automates the population of a Mail-Enabled Security Group based on a mailbox filter.  

.DESCRIPTION
This has been created because the Application Access Policies in Exchange Online do not support dynamic groups. As static lists quickly become outdated our primary goal is to automate this process.  

## Set-EXOSecurityGroupMembers.ps1 [-MailboxFilter <string[OPATH filter]>] [-GroupIdentity <Array[GUID]>] [-DifferentialScope <Int>] [-AutomationPSCredential<String>]

.PARAMETER MailboxFilter
The MailboxFilter parameter details the ObjectId of the Azure Group which contains all the desired owners as members of one group.

.PARAMETER GroupIdentity
The GroupIdentity parameter specifies the target group whose membership you want to modify. Please be aware that users will be removed or added from the group based on the mailbox filter. 

.PARAMETER DifferentialScope
The DifferentialScope parameter defines how many objects can be added or removed from the UserGroups in a single operation of the script. The goal of this setting is throttle bulk changes to limit the impact of misconfiguration by an administrator. What value you choose here will be dictated by your userbase and your script schedule. The default value is set to 10 Objects. 

.PARAMETER AutomationPSCredential
The AutomationPSCredential parameter defines which Azure Automation Cred you would like to use. This account must have the access to Read | Write to Mail Users and Remove Guest Accounts 

.EXAMPLE
Set-EXOSecurityGroupMembers.ps1 -MailboxFilter "EmailAddresses -like '*@contso.com'" -GroupIdentity '0e55190c-73ee-e811-80e9-005056a31be6'

-- SET MEMBERS FOR ROLE GROUPS --

In this example the script will add mailbox users (EmailAddresses -like '*@contso.com') as members to the mail enabled group '0e55190c-73ee-e811-80e9-005056a31be6'

.LINK

Filterable properties for the Filter parameter - https://docs.microsoft.com/en-us/powershell/exchange/filter-properties?view=exchange-ps

Log Analytics Workspace - https://docs.microsoft.com/en-us/azure/azure-monitor/learn/quick-create-workspace

.NOTES
This function requires that you have already created your Azure AD Groups and Role Groups.

Use Get-DistributionGroup <Name> | ft Name,ExchangeObjectId to obtain the GUID information for your group

[AUTHOR]
Joshua Bines, Consultant

Find me on:
* Web:     https://theinformationstore.com.au
* LinkedIn:  https://www.linkedin.com/in/joshua-bines-4451534
* Github:    https://github.com/jbines
  
[VERSION HISTORY / UPDATES]
0.0.1 20200803 - JBINES - Created the bare bones
1.0.0 20200810 - JBINES - [MAJOR RELEASE] Some final touches after testing and rolled into Prod

[TO DO LIST / PRIORITY]

#>
```
