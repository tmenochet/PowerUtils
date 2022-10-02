#requires -version 3

Function Disable-WinDefender {
<#
.SYNOPSIS
    Disable Windows Defender.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Disable-WinDefender completely disables Microsoft Windows Defender antivirus protection.
    Please note that a system reboot is required to make sure all functionalities are disabled.
    WARNING: You should consider this operation is NOT easily reversible and the system will no longer be protected!
    This script is highly inspired from https://bidouillesecurity.com/disable-windows-defender-in-powershell.

.EXAMPLE
    PS C:\> Disable-WinDefender
#>
    [CmdletBinding()]
    Param ()

    # Check if user is elevated
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
        Write-Warning "This command must be launched as an Administrator" 
        return
    }

    Write-Host "[*] Adding Windows Defender exclusions for the whole system..."
    67..90 | Foreach-Object {
        $drive = [char]$_
        Add-MpPreference -ExclusionPath "$($drive):\" -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionProcess "$($drive):\*" -ErrorAction SilentlyContinue
    }

    Write-Host "[*] Setting default actions to 'Allow'..."
    Set-MpPreference -LowThreatDefaultAction Allow -ErrorAction SilentlyContinue
    Set-MpPreference -ModerateThreatDefaultAction Allow -ErrorAction SilentlyContinue
    Set-MpPreference -HighThreatDefaultAction Allow -ErrorAction SilentlyContinue

    Write-Host "[*] Disabling scanning engines..."
    Set-MpPreference -DisableArchiveScanning $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableRemovableDriveScanning $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScanningNetworkFiles $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

    if ((Get-CimInstance -ClassName Win32_OperatingSystem -Verbose:$false).ProductType -ne 1) {
        # Host is a server, Windows Defender can be uninstalled properly
        Write-Host "[*] Uninstalling Windows Defender..."
        try {
            Uninstall-WindowsFeature Windows-Defender -ErrorAction Stop
            Uninstall-WindowsFeature Windows-Defender-Features -ErrorAction Stop
        }
        catch {
            Write-Warning "Windows Defender did not uninstall successfully"
        }
    }

    if ((Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status -eq 'Running') {
        Write-Host "[*] Disabling Windows Defender services..."
        # WdNisSvc : Network Inspection Service 
        # WinDefend : Antivirus Service
        # Sense : Advanced Protection Service
        Invoke-CommandAs -Identity 'NT SERVICE\TrustedInstaller' -ScriptBlock {
            $svc_list = @("WdNisSvc", "WinDefend", "Sense")
            foreach ($svc in $svc_list) {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc") {
                    if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc").Start -eq 4) {
                        Write-Output "[+] Service $svc already disabled"
                    }
                    else {
                        Write-Output "[+] Disabling service $svc (effective after reboot)"
                        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 4
                    }
                }
                else {
                    Write-Output "[+] Service $svc does not exist"
                }
            }
        }

        Write-Host "[*] Disabling Windows Defender drivers..."
        # WdnisDrv : Network Inspection System Driver
        # wdfilter : Mini-Filter Driver
        # wdboot : Boot Driver
        Invoke-CommandAs -Identity 'NT SERVICE\TrustedInstaller' -ScriptBlock {
            $drv_list = @("WdnisDrv", "wdfilter", "wdboot")
            foreach ($drv in $drv_list) {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv") {
                    if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv").Start -eq 4) {
                        Write-Output "[+] Driver $drv already disabled"
                    }
                    else {
                        Write-Output "[+] Disabling driver $drv (effective after reboot)"
                        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv" -Name Start -Value 4
                    }
                }
                else {
                    Write-Output "[+] Driver $drv does not exist"
                }
            }
        }

        Write-Warning "Please reboot the system and run this script again to make sure all functionalities are disabled"
    }
    else {
        Write-Host "[*] Disabling all functionalities..."
        Invoke-CommandAs -Identity 'NT SERVICE\TrustedInstaller' -ScriptBlock {
            # Cloud-delivered protection
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name SpyNetReporting -Value 0
            # Automatic Sample submission
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name SubmitSamplesConsent -Value 0
            # Tamper protection
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name TamperProtection -Value 4
            # Windows Defender
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1
        }
        Write-Host "[*] Done!"
    }
}

Function Local:Invoke-CommandAs {
<#
.SYNOPSIS
    Invoke PowerShell script block as privileged account.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-CommandAs runs PowerShell script block on local computer via scheduled job.

.PARAMETER ScriptBlock
    Specifies the PowerShell script block to run.

.PARAMETER ArgumentList
    Specifies the PowerShell script block arguments.

.PARAMETER Identity
    Specifies the account to use, defaults to 'NT AUTHORITY\SYSTEM'.

.EXAMPLE
    PS C:\> Invoke-CommandAs -ScriptBlock {whoami /groups} -Identity 'NT SERVICE\TrustedInstaller'
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ScriptBlock,

        [Object[]]
        $ArgumentList,

        [ValidateSet('NT AUTHORITY\SYSTEM', 'NT SERVICE\TrustedInstaller')]
        [String]
        $Identity = 'NT AUTHORITY\SYSTEM'
    )

    # Create scheduled job
    try {
        $jobParameters = @{
            Name = [guid]::NewGuid().Guid
            ScheduledJobOption = New-ScheduledJobOption -StartIfOnBattery -ContinueIfGoingOnBattery
        }
        $jobArgumentList = @{
            ScriptBlock  = $ScriptBlock
            Using = @()
        }
        if ($ArgumentList) {
            $jobArgumentList['ArgumentList'] = $ArgumentList
        }
        $usingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [Management.Automation.Language.UsingExpressionAst]},$True)
        if ($usingVariables) {
            $scriptText = $ScriptBlock.Ast.Extent.Text
            $scriptOffSet = $ScriptBlock.Ast.Extent.StartOffset
            foreach ($subExpression in ($usingVariables.SubExpression | Sort-Object { $_.Extent.StartOffset } -Descending)) {
                $name = '__using_{0}' -f (([Guid]::NewGuid().guid) -Replace '-')
                $expression = $subExpression.Extent.Text.Replace('$Using:','$').Replace('${Using:','${'); 
                $value = [Management.Automation.PSSerializer]::Serialize((Invoke-Expression $expression))
                $jobArgumentList['Using'] += [PSCustomObject]@{ Name = $name; Value = $value } 
                $scriptText = $scriptText.Substring(0, ($subExpression.Extent.StartOffSet - $scriptOffSet)) + "`${Using:$name}" + $scriptText.Substring(($subExpression.Extent.EndOffset - $scriptOffSet))
            }
            $jobArgumentList['ScriptBlock'] = [ScriptBlock]::Create($scriptText.TrimStart('{').TrimEnd('}'))
        }
        $jobScriptBlock = [ScriptBlock]::Create(@'
            Param($Parameters)
            $jobParameters = @{}
            if ($Parameters.ScriptBlock)  { $jobParameters['ScriptBlock']  = [ScriptBlock]::Create($Parameters.ScriptBlock) }
            if ($Parameters.ArgumentList) { $jobParameters['ArgumentList'] = $Parameters.ArgumentList }
            if ($Parameters.Using) { 
                $Parameters.Using | % { Set-Variable -Name $_.Name -Value ([Management.Automation.PSSerializer]::Deserialize($_.Value)) }
                Start-Job @JobParameters | Receive-Job -Wait -AutoRemoveJob
            }
            else {
                Invoke-Command @JobParameters
            }
'@)
        $scheduledJob = Register-ScheduledJob  @jobParameters -ScriptBlock $jobScriptBlock -ArgumentList $jobArgumentList -ErrorAction Stop

        # Create scheduled task
        try {
            $scheduleService = New-Object -ComObject ('Schedule.Service')
            $scheduleService.Connect()
            $scheduleTaskFolder = $scheduleService.GetFolder("\")
            $taskDefinition = $scheduleService.NewTask(0)
            $taskDefinition.Settings.StopIfGoingOnBatteries = $false
            $taskDefinition.Settings.DisallowStartIfOnBatteries = $false
            $taskName = [guid]::NewGuid().Guid
            $taskAction = $taskDefinition.Actions.Create(0)
            $taskAction.Path = $scheduledJob.PSExecutionPath
            $taskAction.Arguments = $scheduledJob.PSExecutionArgs 
            Write-Verbose "[Invoke-CommandAs] Registering scheduled task $taskName"
            $registeredTask = $scheduleTaskFolder.RegisterTaskDefinition($taskName, $taskDefinition, 6, $Identity, $null, 5)
            Write-Verbose "[Invoke-CommandAs] Running scheduled task as $Identity"
            $scheduledTask = $registeredTask.Run($null)
            do {
                $scheduledTaskInfo = $scheduleTaskFolder.GetTasks(1) | Where-Object Name -eq $scheduledTask.Name
                Start-Sleep -Milliseconds 100
            }
            while ($scheduledTaskInfo.State -eq 3 -and $scheduledTaskInfo.LastTaskResult -eq 267045)
            do {
                $scheduledTaskInfo = $scheduleTaskFolder.GetTasks(1) | Where-Object Name -eq $scheduledTask.Name
                Start-Sleep -Milliseconds 100
            }
            while ($scheduledTaskInfo.State -eq 4)
            if ($scheduledTaskInfo.LastRunTime.Year -ne (Get-Date).Year) { 
                Write-Warning "[Invoke-CommandAs] Failed to execute scheduled task."
            }
        }
        catch { 
            Write-Error "[Invoke-CommandAs] Task execution failed. $_"
        }
        finally {
            Write-Verbose "[Invoke-CommandAs] Unregistering scheduled task $taskName"
            if ($scheduledTask) { 
                $scheduleTaskFolder.DeleteTask($scheduledTask.Name, 0) | Out-Null
            }
        }

        if ($job = Get-Job -Name $scheduledJob.Name -ErrorAction SilentlyContinue) {
            $job | Wait-Job | Receive-Job -Wait -AutoRemoveJob
        }
    }
    catch { 
        Write-Error $_ 
    }
    finally {
        if ($scheduledJob) {
            Get-ScheduledJob -Id $scheduledJob.Id -ErrorAction SilentlyContinue | Unregister-ScheduledJob -Force -Confirm:$False | Out-Null
        }
    }
}
