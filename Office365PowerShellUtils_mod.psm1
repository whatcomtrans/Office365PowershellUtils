<#
.SYNOPSIS
Filters objects returned by Get-MsolUser for users which have a particular license AccountSkuId.  Requires MSOnline module and active connection to MSOL services.

.EXAMPLE
Get-MsolUser | Find-MsolUsersWithLicense "whatcomtrans:ENTERPRISEPACK"
#>
function Find-MsolUsersWithLicense {
	[CmdletBinding(SupportsShouldProcess=$false)]
	Param(
		[Parameter(Mandatory=$true,Position=0,HelpMessage="Enter the AccountSkuId to filter users for (see Get-MsolAccountSku).")] [string]$AccountSkuId,
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=1,HelpMessage="Object from Get-MsolUser.")] [Object]$msoluser
	)
	Process {
		foreach ($lic in $msoluser.Licenses) {
			Write-Debug $lic
			if ($lic.AccountSkuId -eq $AccountSkuId) {
				$msoluser
			}
		}
	}
}

<#
.SYNOPSIS
Performs one-way sync of user license assignment with group membership.  Requires ActiveDirectory and MSOnline modules and active connection to MSOL services.

.EXAMPLE
TODO
#>
function Update-MsolLicensedUsersFromGroup {
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High",DefaultParameterSetName="SKUFromList")]
	Param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0,HelpMessage="Group(s)")] [Object[]]$ADGroup,
		[Parameter(Mandatory=$true,Position=1,ParameterSetName="SKUFromList",HelpMessage="The AccountSkuId(s) to match group membership against(see Get-MsolAccountSku).  If more then one value provided they are stepped through for each group provided.  If all groups should reference one sku, provide only one.  If each group should match a different sku, provide a sku for each group in same order of groups.")] [String[]]$AccountSkuId,
		[Parameter(Mandatory=$true,Position=1,ParameterSetName="SKUFromGroup",HelpMessage="The AD Group property to retrieve the AccountSkuId to match group membership against(see Get-MsolAccountSku).  Use instead of AccountSkuID.  Defaults to the info/note attribute.")] [alias("Property")] [Object]$GroupSKUProperty = "info",
        [Parameter(Mandatory=$false,Position=2,HelpMessage="Output change objects instead of making the changes.  This causes the cmdlet to return an array of objects which contain the script to run, type of change, etc.")] [Switch]$OutputOnly
	)
	Begin {
		$groupCounter = 0
		if ($AccountSkuId) {
			#use array
			$skuByArray = $true
		} else {
			#use group property
			$skuByArray = $false
		}
		$changes = @{}
		$skuid = ""
		$groupsUsers = @()
		$msolLicUsers = ""
		
		$ChangeTypeScriptBlock = {
			if ($this.RemoveSkuID -ne "" -and $this.AddSkuID -eq "") {
				Return "Remove"
			} elseif ($this.RemoveSkuID -ne "" -and $this.AddSkuID -ne "") {
				Return "Transfer"
			} elseif ($this.RemoveSkuID -eq "" -and $this.AddSkuID -ne "") {
				Return "Add"
			} elseif ($this.RemoveSkuID -eq "" -and $this.AddSkuID -eq "") {
				Return "None"
			}
		}
		
		$SortOrderScriptBlock = {
			switch ($this.ChangeType) {
				Remove {Return 1}
				Transfer {Return 2}
				Add {Return 3}
				default {Return 0}
			}
		}

		$CommandScriptBlock = {
			switch ($this.ChangeType) {
				Remove {Return "Set-MsolUserLicense -UserPrincipalName " + $this.UserPrincipalName + " -RemoveLicenses " + $this.RemoveSkuID}
				Transfer {Return "Set-MsolUserLicense -UserPrincipalName " + $this.UserPrincipalName + " -AddLicenses " + $this.AddSkuID + " -RemoveLicenses " + $this.RemoveSkuID}
				Add {Return "Set-MsolUserLicense -UserPrincipalName " + $this.UserPrincipalName + " -AddLicenses " + $this.AddSkuID}
				default {Return "#No change for user: " + $this.UserPrincipalName}
			}
		}
	}
	Process {
		#For each group
		foreach($valADGroup in $ADGroup) {
			#Get ADGroup, but first make sure it is null so we can detect failure
			$objADGroup = $null
			#If value is a string or somother object passable to Get-ADGroup
			if ($skuByArray) {
				$objADGroup = Get-ADGroup -Identity $valADGroup
			} else {
				$objADGroup = Get-ADGroup -Identity $valADGroup -Properties $GroupSKUProperty
			}
			if ($objADGroup) {	#Group exists
				#Track accross process calls group count
				$groupCounter++
				#Get the skuid
				if ($skuByArray) {	#Using array instead of group property
					if ($AccountSkuId[($groupCounter - 1)]) {
						#only change skuid if there is antoher value in array, this allows for one skuid to match multiple groups
						$newskuid = $AccountSkuId[($groupCounter - 1)]
					}
				} else {			#Using group property instead of array
					if ($objADGroup.$GroupSKUProperty) {$newskuid = $objADGroup.$GroupSKUProperty}
				}
				if ($newskuid) {	#Found skuid, could be from last time
					if ($newskuid -ne $skuid) {	#moving on to new skuid
						$skuid = $newskuid
						$groupsUsers = @()
						#Get licensed users
						$msolLicUsers = Get-MsolUser -EnabledFilter EnabledOnly -All | Find-MsolUsersWithLicense $skuid
					}
					
					#Get group members
					$groupMembers = Get-ADGroupMember -Identity $objADGroup -Recursive | Get-ADUser -Properties UserPrincipalName
					$groupsUsers = $groupsUsers + $groupMembers
					
					
					#Get differences
					$compareResults = Compare-Object -ReferenceObject $groupsUsers -DifferenceObject $msolLicUsers -PassThru -Property UserPrincipalName
					
					foreach ($user in $compareResults) {
						if (!$user.UserPrincipalName) {
							Write-Verbose "Unable to find UserPrincipalName for $user"
						} else {
							if (!$changes.ContainsKey($user.UserPrincipalName)) {
								$newObj = New-Object -TypeName PSObject -Property @{UserPrincipalName = $user.UserPrincipalName; RemoveSkuID = ""; AddSkuID = ""}
								Add-Member -InputObject $newObj -Name 'SortOrder' -Value $SortOrderScriptBlock -MemberType ScriptProperty
								Add-Member -InputObject $newObj -Name 'Command' -Value $CommandScriptBlock -MemberType ScriptProperty
								Add-Member -InputObject $newObj -Name 'ChangeType' -Value $ChangeTypeScriptBlock -MemberType ScriptProperty
                                Add-Member -InputObject $newObj -Name 'Invoke' -Value {Invoke-Expression $this.Command -ErrorAction continue} -MemberType ScriptMethod
								$changes.Add($user.UserPrincipalName, $newObj)
							}
							if ($user.SideIndicator -eq '=>') {	#remove
								($changes.Item($user.UserPrincipalName)).RemoveSkuID = $skuid
							} else {	#add
								($changes.Item($user.UserPrincipalName)).AddSkuID = $skuid
							}
						}
					}
				} else {
					throw "Could not find AccountSkuId with associated group $valADGroup."
				}
			} else {
				throw "Could not find AD group $valADGroup."
			}
		}
	}
	End {
		$ProcessScriptBlock = {
			if ($PSCmdlet.ShouldProcess($_.UserPrincipalName)) {
				Invoke-Expression $_.Command -ErrorAction continue
				Write-Verbose $_.Command
			} else {
				Write-Host $_.Command
			}
		}
		
		$arrayOfChanges = @()
		
		#Convert to simple array
		$changes.GetEnumerator() | ForEach-Object {$arrayOfChanges += $_.Value}
		
		#Execute the commands
        if ($OutputOnly) {
            return $arrayOfChanges | Sort-Object -Property SortOrder
        }else {
		    $arrayOfChanges | Sort-Object -Property SortOrder | ForEach-Object $ProcessScriptBlock
            return ($arrayOfChanges | Sort-Object -Property SortOrder)
        }
        
	}
}

<#
.SYNOPSIS
Performs one-way sync of user usage location based on group membership.  Requires ActiveDirectory and MSOnline modules and active connection to MSOL services.

.EXAMPLE
TODO
#>
function Update-MsolUserUsageLocation {
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="High",DefaultParameterSetName="UsageLocationFromList")]
	Param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0,HelpMessage="Group(s)")] [Object[]]$ADGroup,
		[Parameter(Mandatory=$true,Position=1,ParameterSetName="UsageLocationFromList",HelpMessage="The UsageLocation(s) to set for group membership.  If more then one value provided they are stepped through for each group provided.  If all groups should reference one location, provide only one.  If each group should match a different UsageLocation, provide a value for each group in same order of groups.")] [String[]]$UsageLocation,
		[Parameter(Mandatory=$true,Position=1,ParameterSetName="UsageLocationFromGroup",HelpMessage="The AD Group property to retrieve the UsageLocation value from.  Defaults to the info/note attribute.")] [alias("Property")] [Object]$GroupUsageLocationProperty = "info"
	)
	Begin {
		$groupCounter = 0
		if ($UsageLocation) {
			#use array
			$locationByArray = $true
		} else {
			#use group property
			$locationByArray = $false
		}
		$ProcessScriptBlock = {
			$cmdString = "Set-MSOLUser -UsageLocation '" + $UsageLocation + "' -UserPrincipalName " + $_.UserPrincipalName
			Write-Verbose $cmdString
			if ($PSCmdlet.ShouldProcess($_.UserPrincipalName)) {
				Invoke-Expression $cmdString -ErrorAction continue
			} else {
				Write-Host $cmdString
			}
		}
	}
	Process {
		#TODO Get group and property if using group property value TODO
		
		foreach($valADGroup in $ADGroup) {
			#Get ADGroup, but first make sure it is null so we can detect failure
			$objADGroup = $null
			#If value is a string or some other object passable to Get-ADGroup
			if ($locationByArray) {
				$objADGroup = Get-ADGroup -Identity $valADGroup
			} else {
				$objADGroup = Get-ADGroup -Identity $valADGroup -Properties $GroupSKUProperty
			}
			if ($objADGroup) {	#Group exists
				#Track accross process calls group count
				$groupCounter++
				#Get the skuid
				if ($locationByArray) {	#Using array instead of group property
					if ($UsageLocation[($groupCounter - 1)]) {
						#only change skuid if there is antoher value in array, this allows for one skuid to match multiple groups
						$newUsageLocation = $UsageLocation[($groupCounter - 1)]
					}
				} else {				#Using group property instead of array
					if ($objADGroup.$GroupUsageLocationProperty) {$newUsageLocation = $objADGroup.$GroupUsageLocationProperty}
				}
		
				Get-ADGroupMember -Identity $objADGroup -Recursive | Get-ADUser -Properties UserPrincipalName | ForEach-Object $ProcessScriptBlock		
			}
		}
	}
	End {
	}
}

function Change-ProxyAddress {
    [CmdletBinding(SupportsShouldProcess=$true,DefaultParameterSetName="Add")]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Identity of user to change, takes same as Set-ADUser or pipe a User object.")]
        $Identity,
        [Parameter(Mandatory=$false,Position=1,ValueFromPipeline=$false,HelpMessage="The proxy address to add, without the prefix.  Example, johndoe@domain.com")]
        [String]$ProxyAddress,
        [Parameter(Mandatory=$false,Position=4,ValueFromPipeline=$false,HelpMessage="The prefix.  Default is SMTP")]
        [String]$Prefix="smtp",
        [Parameter(Mandatory=$false,Position=3,ValueFromPipeline=$true,HelpMessage="Identity of user to change, takes same as Set-ADUser or pipe a User object.")]
        [Switch] $IsDefault,
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$true,ParameterSetName="Add",HelpMessage="Add the ProxyAddress with the specified Prefix.")]
        [Switch] $Add,
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$true,ParameterSetName="Remove",HelpMessage="Remove the ProxyAddress with the specified Prefix.")]
        [Switch] $Remove,
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$true,ParameterSetName="Sync",HelpMessage="Sync the list of ProxyAddresses to make sure it includes the user's EmailAddress.")]
        [Switch] $Sync,
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$true,ParameterSetName="Test",HelpMessage="Test to see of the ProxyAddress with the specified Prefix exists.")]
        [Switch] $Test,
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$true,ParameterSetName="GetDefault",HelpMessage="Test to see of the ProxyAddress with the specified Prefix exists.")]
        [Switch] $GetDefault
    )

    process {
        #Handle parameters
        $_identity = $Identity
        [String] $_changeaddress = $ProxyAddress
        [boolean] $_isDefault = $IsDefault
        [String] $_prefix = $Prefix

        #Set initial values
        [boolean] $_exists = $false
        [boolean] $_changed = $false
        [int] $_identityType = 0
        [String] $_syncAddress = ""

        #First, find the user, group or mailbox to change.  Search local AD users, followed by local AD groups and then Mailboxes
        try {
            $_user = Get-ADUser $_identity -Properties proxyAddresses,mail -ErrorAction SilentlyContinue
        }catch {}
        if (!$_user) {
            try {
                $_user = Get-ADGroup $_identity -Properties proxyAddresses,mail -ErrorAction Stop
            } catch {}
            if (!$_user) {
                $_user = Get-Mailbox $_identity
                if ($_user) {
                    $_identityType = 3
                }
            } else {
                $_identityType = 2
            }
        } else {
            $_identityType = 1
        }
        
        #Second, now that we have the "user" object, retrieve the list or proxyAddresses and their current mail address
        switch ($_identityType) {
            0 {throw "Unable to find local AD User, Group or remote Mailbox that matches $_identity"}
            1 {
                [System.Collections.ArrayList] $_addresses = $_user.proxyAddresses
                $_syncAddress = $_user.mail
              }
            2 {
                [System.Collections.ArrayList] $_addresses = $_user.proxyAddresses
                $_syncAddress = $_user.mail
              }
            3 {
                [System.Collections.ArrayList] $_addresses = $_user.EmailAddresses
                $_syncAddress = ($_user.PrimarySmtpAddress)
              }
        }
        
        #Third, handle switches
        if ($Sync) {
            $_isDefault = $true
            $_changeaddress = $_syncAddress
        }

        if ($_isDefault) {
            $_prefix = $_prefix.ToUpper()
        } else {
            $_prefix = $_prefix.ToLower()
        }

        [String] $_changeproxyaddress = $_prefix + ":" + $_changeaddress

        #Fourth, iterate the list of addresses
        for ($i=0; $i -lt $_addresses.Count; $i++) {
            [String] $_address = $_addresses[$i]
            if ($_address -Like ($_prefix + ":*")) {
                #Found a proxy address with matching prefix
                if ($_address -like $_changeproxyaddress) {
                    #already exists
                    #if it should not be the default, change it
                    if (!$_isDefault -and ($_address -CLike ($_prefix.ToUpper() + ":*"))) {
                        #found the current default, need to change
                        $_addresses[$i] = $_address.Replace($_prefix.ToUpper(), $_prefix)
                        $_changed = $true
                    }

                    #if it should be the default and it is not, change it
                    if ($_isDefault -and ($_address -CLike ($_prefix.ToLower() + ":*"))) {
                        #found the current default, need to change
                        $_addresses[$i] = $_address.Replace($_prefix.ToLower(), $_prefix)
                        $_changed = $true
                    }

                    #note that it exists so that Add does not run
                    $_exists = $true
            
                    #if this is a remove process, remove it
                    if ($Remove) {
                        #Remove it
                        $_addresses.RemoveAt($i)
                        $_changed = $true
                    }
                } else {
                    #a different proxy with same prefix
                    if ($_isDefault -and ($_address -CLike ($_prefix + ":*"))) {
                        #if just looking for default the just return value here
                        if ($GetDefault) {
                            return $_address
                        }
                        #found the current default, need to change
                        $_addresses[$i] = $_address.Replace($_prefix, $_prefix.ToLower())
                        $_changed = $true
                    }
                }
            }
        }

        #Fifth, handle the Test and Add switches
        if ($Test) {
            if ($_exists) {
                return $true
            } else {
                return $false
            }
        }

        if (($_exists -eq $false) -and ($Add -or $Sync)) {
                #proxy not found, add it
                $_addresses += $_changeproxyaddress
                $_changed = $true
        }

        #Sixth, make the changes
        [Array] $_changedaddresses = $_addresses.ToArray()
        #$_changedaddresses
        if ($_changed) {
            if ($_addresses.Count -gt 0) {
                if ($_identityType -eq 3) {
                    Set-Mailbox -Identity ($_user.UserPrincipalName) -EmailAddresses $_changedaddresses
                } else {
                    Set-ADObject -Identity $_user -Replace @{proxyAddresses=$_changedaddresses}
                }
            } else {
                if ($_identityType -eq 3) {
                    Set-Mailbox -Identity ($_user.UserPrincipalName) -EmailAddresses $_changedaddresses
                } else {
                    Set-ADObject -Identity $_user -Clear proxyAddresses
                }
            }
        }
    }
}

<#
.SYNOPSIS
Makes it easy to add a proxyAddress to a user in local Active Directory (used with DirSync).

.EXAMPLE
Add-ProxyAddress -Identity TestProxy -ProxyAddress "testproxy1@ridewta.com" -IsDefault -Confirm
#>
function Add-ProxyAddress {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Identity of user to change, takes same as Set-ADUser or pipe a User object.")]
        $Identity,
        [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$false,HelpMessage="The proxy address, without the prefix.  Example, johndoe@domain.com")]
        [String]$ProxyAddress,
        [Parameter(Mandatory=$false,Position=3,ValueFromPipeline=$false,HelpMessage="The proxy address prefix (smtp, sip, x500, etc)")]
        [String]$Prefix="smtp",
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$true,HelpMessage="Should the proxyAddress be the default.")]
        [Switch] $IsDefault
    )

    process {
        Change-ProxyAddress -Identity $Identity -ProxyAddress $ProxyAddress -Prefix $Prefix -IsDefault:$IsDefault -Add
    }
}

<#
.SYNOPSIS
Makes it easy to remove a proxyAddress from a user in local Active Directory (used with DirSync).

.EXAMPLE
Remove-ProxyAddress -Identity TestProxy -ProxyAddress "testproxy1@ridewta.com" -IsDefault -Confirm
#>
function Remove-ProxyAddress {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Identity of user to change, takes same as Set-ADUser or pipe a User object.")]
        $Identity,
        [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$false,HelpMessage="The proxy address, without the prefix.  Example, johndoe@domain.com")]
        [String]$ProxyAddress,
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$false,HelpMessage="The proxy address prefix (smtp, sip, x500, etc)")]
        [String]$Prefix="smtp"
    )

    process {
        Change-ProxyAddress -Identity $Identity -ProxyAddress $ProxyAddress -Prefix $Prefix -IsDefault:$false -Remove
    }
}

<#
.SYNOPSIS
Makes it easy to set the default proxyAddress for a user in local Active Directory (used with DirSync).  It will add the address if it does not exist.

.EXAMPLE
Set-ProxyAddress -Identity TestProxy -ProxyAddress "testproxy1@ridewta.com" -IsDefault -Confirm
#>
function Set-ProxyAddress {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Identity of user to change, takes same as Set-ADUser or pipe a User object.")]
        $Identity,
        [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$false,HelpMessage="The proxy address, without the prefix.  Example, johndoe@domain.com")]
        [String]$ProxyAddress,
        [Parameter(Mandatory=$false,Position=3,ValueFromPipeline=$false,HelpMessage="The proxy address prefix (smtp, sip, x500, etc)")]
        [String]$Prefix="smtp",
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$true,HelpMessage="Should the proxyAddress be the default.")]
        [Switch] $IsDefault
    )

    process {
        Change-ProxyAddress -Identity $Identity -ProxyAddress $ProxyAddress -Prefix $Prefix -IsDefault:$IsDefault -Add
    }
}

<#
.SYNOPSIS
Makes it easy to sync a user's EmailAddress with the collection of proxyAddresses.  The user's EmailAddress will added if missing and set as the default SMTP ProxyAddress in local Active Directory (used with DirSync).

.EXAMPLE
Sync-ProxyAddress -Identity TestProxy -Confirm
#>
function Sync-ProxyAddress {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Identity of user to change, takes same as Set-ADUser or pipe a User object.")]
        $Identity
    )

    process {
        Change-ProxyAddress -Identity $Identity -ProxyAddress "" -Prefix "smtp" -IsDefault:$true -Sync
    }
}

<#
.SYNOPSIS
Makes it easy to test if a proxyAddress exists for specified user in local Active Directory (used with DirSync).

.EXAMPLE
Test-ProxyAddress -Identity TestProxy -ProxyAddress "testproxy1@ridewta.com"
#>
function Test-ProxyAddress {
    [CmdletBinding(SupportsShouldProcess=$false)]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Identity of user to change, takes same as Set-ADUser or pipe a User object.")]
        $Identity,
        [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$false,HelpMessage="The proxy address, without the prefix.  Example, johndoe@domain.com")]
        [String]$ProxyAddress,
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$false,HelpMessage="The proxy address prefix (smtp, sip, x500, etc)")]
        [String]$Prefix="smtp"
    )

    process {
        return Change-ProxyAddress -Identity $Identity -ProxyAddress $ProxyAddress -Prefix $Prefix -Test
    }
}

<#
.SYNOPSIS
Returns the default ProxyAddress for the specified Prefix (defaults to SMTP) in local Active Directory (used with DirSync).

.EXAMPLE
Get-ProxyAddressDefault -Identity TestProxy
#>
function Get-ProxyAddressDefault {
    [CmdletBinding(SupportsShouldProcess=$false)]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Identity of user to change, takes same as Set-ADUser or pipe a User object.")]
        $Identity,
        [Parameter(Mandatory=$false,Position=1,ValueFromPipeline=$false,HelpMessage="The proxy address prefix (smtp, sip, x500, etc)")]
        [String]$Prefix="smtp"
    )

    process {
        return Change-ProxyAddress -Identity $Identity -ProxyAddress "" -Prefix $Prefix -IsDefault -GetDefault
    }
}

<#
.SYNOPSIS
Adds display name and email address to a security group in local Active Directory thus enabling DirSync to add it as an Exchange Online Distribution Group.  Really just a shortcut to Set-ADGroup.

.EXAMPLE
Enable-SecurityGroupAsDistributionGroup -Identity GroupA -DisplayName "Group A" -EmailAddress "groupa@company.com"
#>
function Enable-SecurityGroupAsDistributionGroup {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Identity of group to change, takes same as Set-ADGroup or pipe a group object.")]
        $Identity,
        [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$false,HelpMessage="The display name (for the address book).")]
        [String]$DisplayName,
        [Parameter(Mandatory=$true,Position=2,ValueFromPipeline=$false,HelpMessage="The email address for the group.")]
        [String]$EmailAddress,
        [Parameter(Mandatory=$false,Position=3,ValueFromPipeline=$false,HelpMessage="Hide this group from the address list.  Defaults to false.")]
        [Switch]$Hide
    )

    process {
        $_group = Get-ADGroup -Identity $Identity -Properties DisplayName,mail,msExchHideFromAddressLists
        $_group.DisplayName = $DisplayName
        $_group.mail = $EmailAddress
        if ($Hide) {
            $_group.msExchHideFromAddressLists = $true
        } elseif ($_group.msExchHideFromAddressLists) {
            $_group.msExchHideFromAddressLists = $false
        }
        Set-ADGroup -Instance $_group
        Sync-ProxyAddress $Identity
    }
}

<#
.SYNOPSIS
Removes display name and email address to a security group in local Active Directory thus enabling DirSync to remove it as an Exchange Online Distribution Group.  Really just a shortcut to Set-ADGroup.

.EXAMPLE
Disable-SecurityGroupAsDistributionGroup -Identity GroupA
#>
function Disable-SecurityGroupAsDistributionGroup {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Identity of group to change, takes same as Set-ADGroup or pipe a group object.")]
        $Identity
    )

    process {
        $_group = Get-ADGroup -Identity $Identity -Properties DisplayName,mail
        Remove-ProxyAddress $Identity -ProxyAddress $_group.mail
        Set-ADGroup -Identity $Identity -Clear DisplayName,mail
    }
}

<#
.SYNOPSIS
Starts directory sync

.EXAMPLE
Start-DirSync
#>
function Start-DirSync {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,Position=0,ValueFromPipeline=$false,HelpMessage="ADSync server to invoke command on.")]
            [String]$ComputerName
    )
    if ($ComputerName.length -ge 1) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {Import-Module ADSync; Start-ADSyncSyncCycle -PolicyType Delta}
    }
}

Set-Alias -Name Force-DirSync -Value Start-DirSync -Description "Renamed Force-DirSync to Start-DirSync for a more compiant verb.  Alias for backards compatibility."

function Get-NextDirSync {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,Position=0,ValueFromPipeline=$false,HelpMessage="ADSync server to invoke command on.")]
            [String]$ComputerName
    )
    if ($ComputerName.length -ge 1) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {Import-Module ADSync; [DateTime]::Parse((get-adsyncscheduler).NextSyncCycleStartTimeInUTC.ToString() + " GMT");}
    }
}
<#
.SYNOPSIS
This suspends a user mailbox by transitioning it to a shared mailbox, hiding it and preventing it from recieving email.
This is used for employees who's role no longer requires email but may again one day.

.EXAMPLE
Suspend-UserMailbox -Identity UserA
#>
function Suspend-UserMailbox {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Mailbox of user to suspend, takes same as Get-Mailbox.")]
        [String] $Identity
    )

    process {
        $mb = Get-Mailbox $Identity

        #Change mailbox to Shared
        Set-Mailbox -Identity ($mb.Alias) -Type Shared -ErrorAction Continue

        #Hide in GAL
        Set-ADUser -Identity ($Identity) -Replace @{msExchHideFromAddressLists = $true}
        
        #Block from recieving email
        Set-Mailbox -Identity ($mb.Alias) -AcceptMessagesOnlyFrom "no-reply@ridewta.com"

        #Remove from any AD Groups which are also Distribution Groups
        ((Get-ADUser -Identity $Identity -Properties MemberOf).MemberOf | Get-ADGroup) | ForEach-Object {if (Get-DistributionGroup -Identity $_.Name -ErrorAction SilentlyContinue) {Remove-ADGroupMember -Identity ($_.SamAccountName) -Member $Identity -Confirm:$false}}

        #Remove and distribution groups for which the mailbox is a member
        Clear-MailboxMemberOf $mb.Alias -Confirm:$false
    }
}

<#
.SYNOPSIS
This reverses the Suspend-UserMailbox cmdlet.
This resumes a user mailbox by transitioning it fram a shared mailbox, un-hiding it and allowing it to recieve email.
This is used for employees who's role once again requires email.

.EXAMPLE
Resume-UserMailbox -Identity UserA
#>
function Resume-UserMailbox {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Mailbox of user to suspend, takes same as Get-Mailbox.")]
        [String] $Identity
    )

    process {
        $mb = Get-Mailbox $Identity

        #Change mailbox to Regular
        Set-Mailbox -Identity ($mb.Identity) -Type Regular -ErrorAction Continue

        #Show in GAL
        Set-ADUser -Identity ($mb.Alias) -Replace @{msExchHideFromAddressLists = $false}
        
        #Allow recieving email
        Set-Mailbox -Identity ($mb.Identity) -AcceptMessagesOnlyFrom $null

        #User will need to be added back to any distribution lists via another process
    }
}


<#
.SYNOPSIS
Tests to see if a mailbox with a given identity exists, returns boolean

.EXAMPLE
Test-Mailbox -Identity UserA
#>
function Test-Mailbox {
    [CmdletBinding(SupportsShouldProcess=$false)]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Identity to test for.")]
        [String] $Identity
    )

    process {
        return [bool] (Get-Mailbox $Identity -ErrorAction SilentlyContinue)
    }
}

# use-cas -SkipUpdate
# Connect-Office365 -Credential (Get-Credential)


function Get-MailboxMemberOf {
    [CmdletBinding(SupportsShouldProcess=$false)]
    Param (
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String] $Identity
    )
    Process {
        $mb = Get-mailbox $Identity 
        forEach($g in Get-DistributionGroup) {
            Get-DistributionGroupmember $g.Name | Where-Object Guid -eq $mb.Guid | %{Write-Output $g}
        }
    }
}

function Clear-MailboxMemberOf {
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param (
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String] $Identity
    )
    Process {
        (Get-MailboxMemberOf $Identity) | Remove-DistributionGroupMember -Member $Identity -BypassSecurityGroupManagerCheck -Confirm:$false
    }
}

# TODO: This cmdlet needs more documentation, better parameter settings and better error checking.
function Connect-Office365 {
	[CmdletBinding(SupportsShouldProcess=$false, DefaultParameterSetName="Username")]
	Param(
		[Parameter(Mandatory=$false,ParameterSetName="Username",HelpMessage="Credentials")]
		    [String] $Username,
		[Parameter(Mandatory=$false,ParameterSetName="Credentials",HelpMessage="Credentials")]
		    [System.Management.Automation.PSCredential] $Credential,
        [Parameter(Mandatory=$false,ParameterSetName="CredentialsFile", HelpMessage="Path to credentials")]
            [String] $CredentialPath,
        [Parameter(Mandatory=$false)]
            [String] $CertificateFilePath,
        [Parameter(Mandatory=$false)]
            [SecureString] $CertificatePassword,
        [Parameter(Mandatory=$false)]
            [String] $CertificateThumbPrint,
        [Parameter(Mandatory=$false)]
            [String] $AppID,
        [Parameter(Mandatory=$false)]
            [String] $Organization,
        [Parameter(Mandatory=$false)]
            [Switch] $AvoidMFA,
        [Parameter(Mandatory=$false)]
            [Switch] $SkipSharePoint,
        [Parameter(Mandatory=$false)]
            [Switch] $SkipExchange,
        [Parameter(Mandatory=$false)]
            [Switch] $SkipTeams,
        [Parameter(Mandatory=$false)]
            [Switch] $SkipComplianceCenter
    )
    
    Process {

        #Prompt for credential if not provided
        if ($CredentialPath) {
            $Credential = Import-PSCredential -Path $CredentialPath
        }
        if ($Username) {
            $Credential = Get-Credential -UserName $Username -Message "Office 365 Credentials"
        }

        if (!$Credential) {
            $Credential = Get-Credential
        }

        #Connect to MSOLService with credential
        Connect-MsolService -Credential $Credential

        #Connect to SharePoint
        if (!$SkipSharePoint) {
            Connect-SPOService -Credential $Credential
        }

        #Connect to Teams
        if (!$SkipTeams) {
            Connect-MicrosoftTeams -Credential $Credential
        }

        #Connect to Exchange Online
        if (!$SkipExchange) {
            <# Support for connection via certificate
            See https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps
            and https://docs.microsoft.com/en-us/azure/automation/shared-resources/certificates
            #>
            if ($AvoidMFA -or $AppID) {
                if ($AppID) {
                    if ($CertificateFilePath) {
                        Connect-ExchangeOnline -CertificateFilePath $CertificateFilePath -CertificatePassword $CertificatePassword -AppId $AppID -Organization $Organization
                    } elseif ($CertificateThumbPrint) {
                        Connect-ExchangeOnline -CertificateThumbprint $CertificateThumbPrint -AppId $AppID -Organization $Organization
                    } else {
                        Write-Warning "Exchange not loaded.  CertificateFilePath or CertificateThumbprint required.  See https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps"
                    }
                } else {
                    # Connect another way?  The old way?  Essentialy if AvoidMFA, this currently is same as SkipExchange.
                    Write-Warning -Message "Exchange not loaded.  Currently no none MFA connection to Exchange Online available, skipping connection to Exchange Online"
                }
            } else {
                Connect-ExchangeOnline -UserPrincipalName $Credential.UserName
            }
        }

        if (!$SkipComplianceCenter) {
            # IPPSSession supports both MFA and basic connect
            if ($AvoidMFA) {
                # Basic
                Connect-IPPSSession -Credential $Credential
            } else {
                # MFA
                Connect-IPPSSession -UserPrincipalName $Credential.UserName
            }
        }
    }
}

Export-ModuleMember -Function "Find-MsolUsersWithLicense", "Update-MsolLicensedUsersFromGroup", "Update-MsolUserUsageLocation", "Add-ProxyAddress", "Remove-ProxyAddress", "Set-ProxyAddress", "Sync-ProxyAddress", "Test-ProxyAddress", "Get-ProxyAddressDefault", "Enable-SecurityGroupAsDistributionGroup", "Disable-SecurityGroupAsDistributionGroup", "Start-DirSync", "Suspend-UserMailbox", "Resume-UserMailbox", "Test-Mailbox", "Get-NextDirSync", "Get-MailboxMemberOf", "Clear-MailboxMemberOf", "Use-Office365", "Connect-Office365" -Alias "Force-DirSync"
