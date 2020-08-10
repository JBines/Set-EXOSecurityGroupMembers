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

Param 
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]$MailboxFilter,
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]$GroupIdentity,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Int]$DifferentialScope = 10,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]$AutomationPSCredential
)

    #Set VAR
    $counter = 0

# Success Strings
    $sString0 = "OUT-CMDlet:Remove-DistributionGroupMember"
    $sString1 = "IN-CMDlet:Add-DistributionGroupMember"

    # Info Strings
    $iString0 = "Processing Distribution Group"

# Warn Strings
    $wString0 = "CMDlet:Measure-Object;No Users found from filter query"
    $wString1 = "CMDlet:Measure-Object;No Users found in group identity"

# Error Strings

    $eString2 = "Hey! You made it to the default switch. That shouldn't happen might be a null or returned value."
    $eString3 = "Hey! You hit the -DifferentialScope limit of $DifferentialScope. Let's break out of this loop"
    $eString4 = "Hey! Help us out and put some users in the group."

# Debug Strings
    #$dString1 = ""

    #Load Functions

    function Write-Log([string[]]$Message, [string]$LogFile = $Script:LogFile, [switch]$ConsoleOutput, [ValidateSet("SUCCESS", "INFO", "WARN", "ERROR", "DEBUG")][string]$LogLevel)
    {
           $Message = $Message + $Input
           If (!$LogLevel) { $LogLevel = "INFO" }
           switch ($LogLevel)
           {
                  SUCCESS { $Color = "Green" }
                  INFO { $Color = "White" }
                  WARN { $Color = "Yellow" }
                  ERROR { $Color = "Red" }
                  DEBUG { $Color = "Gray" }
           }
           if ($Message -ne $null -and $Message.Length -gt 0)
           {
                  $TimeStamp = [System.DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
                  if ($LogFile -ne $null -and $LogFile -ne [System.String]::Empty)
                  {
                         Out-File -Append -FilePath $LogFile -InputObject "[$TimeStamp] [$LogLevel] $Message"
                  }
                  if ($ConsoleOutput -eq $true)
                  {
                         Write-Host "[$TimeStamp] [$LogLevel] :: $Message" -ForegroundColor $Color

                    if($AutomationPSCredential)
                    {
                         Write-Output "[$TimeStamp] [$LogLevel] :: $Message"
                    } 
                  }
           }
    }

    #Validate Input Values From Parameter 

    Try{

        if ($AutomationPSCredential) {
            
            $Credential = Get-AutomationPSCredential -Name $AutomationPSCredential

            #Connect-AzureAD -Credential $Credential
            
            $ExchangeOnlineSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $Credential -Authentication Basic -AllowRedirection -Name $ConnectionName 
            Import-Module (Import-PSSession -Session $ExchangeOnlineSession -AllowClobber -DisableNameChecking) -Global

            }

        #New Array and Count of Users from Azure Group
        $Mailboxes = Get-Mailbox -Filter $MailboxFilter -ResultSize Unlimited

        #Check if Owners Group is $Null
        $MailboxesNull = $False
        if($Mailboxes.count -eq 0){
            $MailboxesNull = $True
            If($?){Write-Log -Message $wString0 -LogLevel WARN -ConsoleOutput}
        }
    }
    
    Catch{
    
        $ErrorMessage = $_.Exception.Message
        Write-Error $ErrorMessage

            If($?){Write-Log -Message $ErrorMessage -LogLevel Error -ConsoleOutput}

        Break

    }

    #foreach($ExchangeGroup in $ExchangeGroups){
        
        Write-Log -Message "$iString0 - $GroupIdentity" -LogLevel INFO -ConsoleOutput

        #Catch bad calls for role group members from dropping members 
        try {
            
            $ExchangeGroupMember = $null
            $ExchangeGroupMember = Get-DistributionGroupMember -Identity $GroupIdentity 
            
        }
        catch {
            $ErrorMessage = $_.Exception.Message

            If($?){Write-Log -Message $ErrorMessage -LogLevel Error -ConsoleOutput}

            Break
        }

        $ExchangeGroupMemberNULL = $False

        if($ExchangeGroupMember.count -eq 0){
            $ExchangeGroupMemberNULL = $True
            If($?){Write-Log -Message $wString1 -LogLevel WARN -ConsoleOutput}
        }

        switch ($ExchangeGroupMemberNULL) {
            {(-not($ExchangeGroupMemberNULL))-and(-not($MailboxesNull))}{ 
                                                                                    
                                                                                    #Compare Lists and find missing users those who should be removed. 
                                                                                    $assessUsers = Compare-Object -ReferenceObject $Mailboxes.ExternalDirectoryObjectId -DifferenceObject $ExchangeGroupMember.ExternalDirectoryObjectId | Where-Object {$_.SideIndicator -ne "=="}
                                                                                    
                                                                                    if($null -ne $assessUsers){

                                                                                        Foreach($objUser in $assessUsers){  

                                                                                            if ($counter -lt $DifferentialScope) {

                                                                                                # <= -eq Add Object
                                                                                                # = -eq Skip
                                                                                                # => -eq Remove Object

                                                                                                Switch ($objUser.SideIndicator) {
                                                                                
                                                                                                    "=>" { 
                                                                                                    
                                                                                                        $objID = $objUser.InputObject
                                                                                                        $objUPN = (Get-Recipient -Identity $objID).PrimarySmtpAddress 
                                                                                                        $objGroupID = $GroupIdentity

                                                                                                        try {

                                                                                                            Remove-DistributionGroupMember $objGroupID -Member $objUPN -BypassSecurityGroupManagerCheck -Confirm:$false
                                                                                                            if($?){Write-Log -Message "$sString0;DLGroup:$GroupIdentity;ObjectId:$objUPN" -LogLevel SUCCESS -ConsoleOutput}
                        
                                                                                                        }
                                                                                                        catch {
                                                                                                            Write-log -Message $_.Exception.Message -ConsoleOutput -LogLevel ERROR
                                                                                                            Break                                                                                   
                                                                                                        }
                                                                                                        
                                                                                                        #Increase the count post change
                                                                                                        $counter++
                                                                                
                                                                                                        $objID = $null
                                                                                                        $objGroupID = $null
                                                                                                        $objUPN = $null
                                                                                                        
                                                                                                            }
                                                                                
                                                                                                    "<=" { 

                                                                                                        $objID = $objUser.InputObject
                                                                                                        $objUPN = (Get-Recipient -Identity $objID).PrimarySmtpAddress 
                                                                                                        $objGroupID = $GroupIdentity

                                                                                                        Add-DistributionGroupMember $objGroupID -Member $objUPN -BypassSecurityGroupManagerCheck -Confirm:$false
                                                                                                        if($?){Write-Log -Message "$sString1;DLGroup:$GroupIdentity;ObjectId:$objUPN" -LogLevel SUCCESS -ConsoleOutput}

                                                                                                        #Increase the count post change
                                                                                                        $counter++
                                                                                
                                                                                                        $objID = $null
                                                                                                        $objGroupID = $null
                                                                                                        $objUPN = $null
                                                                                
                                                                                                            }
                                                                                
                                                                                                    Default {Write-log -Message $eString2 -ConsoleOutput -LogLevel ERROR }
                                                                                                }
                                                                                            }
                                                                                
                                                                                            else {
                                                                                                       
                                                                                                #Exceeded couter limit
                                                                                                Write-log -Message $eString3 -ConsoleOutput -LogLevel ERROR
                                                                                                Break
                                                                                
                                                                                            }  
                                                                                
                                                                                        }
                                                                                    }

                                                                                }
            {($ExchangeGroupMemberNULL-and(-not($MailboxesNull)))}{ 
                                                                                
                                                                                foreach($objGroupMember in $Mailboxes){
                                                                                    if ($counter -lt $DifferentialScope) {

                                                                                        $objID = $objGroupMember.ExternalDirectoryObjectId
                                                                                        $objUPN = (Get-Recipient -Identity $objID).PrimarySmtpAddress 
                                                                                        $objGroupID = $GroupIdentity

                                                                                                        Add-DistributionGroupMember $objGroupID -Member $objUPN -BypassSecurityGroupManagerCheck -Confirm:$false
                                                                                                        if($?){Write-Log -Message "$sString1;DLGroup:$GroupIdentity;ObjectId:$objUPN" -LogLevel SUCCESS -ConsoleOutput}

                                                                                        #Increase the count post change
                                                                                        $counter++
                                                                
                                                                                        $objID = $null
                                                                                        $objGroupID = $null
                                                                                        $objUPN = $null
                                                                                    }
                                                                                    else {
                                                                                    
                                                                                        #Exceeded couter limit
                                                                                        Write-log -Message $eString3 -ConsoleOutput -LogLevel ERROR
                                                                                        Break
                                                                        
                                                                                    }  
                                                                                }
                                                                            }
            {(-not($ExchangeGroupMemberNULL))-and($MailboxesNull)}{ 
                                                                                    
                                                                            foreach($objExchangeGroupMember in $ExchangeGroupMember){
                                                                                if ($counter -lt $DifferentialScope) {
                                                                                
                                                                                    $objID = $objExchangeGroupMember.ExternalDirectoryObjectId
                                                                                    $objUPN = (Get-Recipient -Identity $objID).PrimarySmtpAddress 
                                                                                    $objGroupID = $GroupIdentity

                                                                                    try {

                                                                                            Remove-DistributionGroupMember $objGroupID -Member $objUPN -BypassSecurityGroupManagerCheck -Confirm:$false
                                                                                            if($?){Write-Log -Message "$sString0;DLGroup:$GroupIdentity;ObjectId:$objUPN" -LogLevel SUCCESS -ConsoleOutput}
    
                                                                                    }
                                                                                    catch {
                                                                                        Write-log -Message $_.Exception.Message -ConsoleOutput -LogLevel ERROR
                                                                                        Break                                                                                   
                                                                                    }
                                                                
                                                                                    #Increase the count post change
                                                                                    $counter++
                                                                                    
                                                                                    $objID = $null
                                                                                    $objGroupID = $null
                                                                                    $objUPN = $null

                                                                                }

                                                                                else {
                                                                                
                                                                                    #Exceeded couter limit
                                                                                    Write-log -Message $eString3 -ConsoleOutput -LogLevel ERROR
                                                                                    Break
                                                                    
                                                                                }      
                                                                            }
                                                                        }
            Default {Write-Log -Message $eString4 -LogLevel ERROR -ConsoleOutput}
        }
    #}

if ($AutomationPSCredential) {
    
    #Invoke-Command -Session $ExchangeOnlineSession -ScriptBlock {Remove-PSSession -Session $ExchangeOnlineSession}

    #Disconnect-AzureAD
}
