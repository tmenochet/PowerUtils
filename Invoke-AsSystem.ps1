#requires -version 3

Function Invoke-AsSystem {
<#
.SYNOPSIS
    Invoke PowerShell script block as NT\AUTHORITY SYSTEM.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-PowerExec runs PowerShell script block on local computer via scheduled job.

.PARAMETER ScriptBlock
    Specifies the PowerShell script block to run.

.PARAMETER ArgumentList
    Specifies the PowerShell script block arguments.

.EXAMPLE
    PS C:\> Invoke-AsSystem -ScriptBlock {whoami}
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ScriptBlock,

        [Object[]]
        $ArgumentList
    )

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

        Invoke-ScheduledTask -Command $scheduledJob.PSExecutionPath -Arguments $scheduledJob.PSExecutionArgs

        $job = Get-Job -Name $scheduledJob.Name -ErrorAction SilentlyContinue
        if ($job) {
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

Function Local:Invoke-ScheduledTask {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [String]
        $Command,

        [String]
        $Arguments
    )
    try {
        $scheduleService = New-Object -ComObject ('Schedule.Service')
        $scheduleService.Connect()
        $scheduleTaskFolder = $scheduleService.GetFolder("\")
        $taskDefinition = $scheduleService.NewTask(0)
        $taskDefinition.Settings.StopIfGoingOnBatteries = $false
        $taskDefinition.Settings.DisallowStartIfOnBatteries = $false
        $taskName = [guid]::NewGuid().Guid
        $taskAction = $taskDefinition.Actions.Create(0)
        $taskAction.Path = $Command
        $taskAction.Arguments = $Arguments
        $registeredTask = $scheduleTaskFolder.RegisterTaskDefinition($taskName, $taskDefinition, 6, 'System', $null, 5)
        $scheduledTask = $registeredTask.Run($null)
        do {
            $scheduledTaskInfo = $scheduleTaskFolder.GetTasks(1) | Where-Object Name -eq $scheduledTask.Name; Start-Sleep -Milliseconds 100
        }
        while ($scheduledTaskInfo.State -eq 3 -and $scheduledTaskInfo.LastTaskResult -eq 267045)
        do {
            $scheduledTaskInfo = $scheduleTaskFolder.GetTasks(1) | Where-Object Name -eq $scheduledTask.Name; Start-Sleep -Milliseconds 100
        }
        while ($scheduledTaskInfo.State -eq 4)
        if ($scheduledTaskInfo.LastRunTime.Year -ne (Get-Date).Year) { 
            Write-Error 'Task execution failed.'
            return 
        }
    }
    catch { 
        Write-Error $_ 
    }
    finally {
        if ($scheduledTask) { 
            $scheduleTaskFolder.DeleteTask($scheduledTask.Name, 0) | Out-Null
        }
    }
}
