Function Invoke-AsLoggedOnUser {
<#
.SYNOPSIS
    Invoke PowerShell script block as an account which is logged in.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-AsLoggedOnUser runs PowerShell script block on local computer via scheduled task and retrieves output via a named pipe.

.PARAMETER ScriptBlock
    Specifies the PowerShell script block to run.

.PARAMETER ArgumentList
    Specifies the PowerShell script block arguments.

.PARAMETER Identity
    Specifies the account to use, defaults to 'NT SERVICE\TrustedInstaller'.

.EXAMPLE
    PS C:\> Invoke-AsLoggedOnUser -ScriptBlock {whoami} -Identity 'ADATUM\testuser'
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ScriptBlock,

        [Object[]]
        $ArgumentList,

        [String]
        $Identity = 'NT SERVICE\TrustedInstaller'
    )

    # Init named pipe client
    $timeout = 10000 # 10s
    $pipename = [guid]::NewGuid().Guid
    $pipeclient = New-Object IO.Pipes.NamedPipeClientStream('localhost', $pipename, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Impersonation)

    # Build loader
    $loader = ''
    $loader += '$s = New-Object IO.Pipes.NamedPipeServerStream(''' + $pipename + ''', 3); '
    $loader += '$s.WaitForConnection(); '
    $loader += '$r = New-Object IO.StreamReader $s; '
    $loader += '$x = ''''; '
    $loader += 'while (($y=$r.ReadLine()) -ne ''''){$x+=$y+[Environment]::NewLine}; '
    $loader += '$z = [ScriptBlock]::Create($x); '
    $loader += '& $z'
    $argument = '-NoP -NonI -W 1 -C "' + $loader + '"'

    # Build payload
    $script = ''
    $script += '[ScriptBlock]$scriptBlock = {' + $ScriptBlock.Ast.Extent.Text + '}' + [Environment]::NewLine -replace '{{','{' -replace '}}','}'
    if ($ArgumentList) {
        $args = $ArgumentList -join ','
        $script += '$args = ' + $args + [Environment]::NewLine
    }
    else {
        $script += '$args = $null' + [Environment]::NewLine
    }
    $script += '$output = [Management.Automation.PSSerializer]::Serialize(((New-Module -ScriptBlock $scriptBlock -ArgumentList $args -ReturnResult) *>&1))' + [Environment]::NewLine
    $script += '$encOutput = [char[]]$output' + [Environment]::NewLine
    $script += '$writer = [IO.StreamWriter]::new($s)' + [Environment]::NewLine
    $script += '$writer.AutoFlush = $true' + [Environment]::NewLine
    $script += '$writer.WriteLine($encOutput)' + [Environment]::NewLine
    $script += '$writer.Dispose()' + [Environment]::NewLine
    $script += '$r.Dispose()' + [Environment]::NewLine
    $script += '$s.Dispose()' + [Environment]::NewLine
    $script = $script -creplace '(?m)^\s*\r?\n',''
    $payload = [char[]] $script

    # Create scheduled task
    try {
        $scheduleService = New-Object -ComObject ('Schedule.Service')
        $scheduleService.Connect()
        $scheduleTaskFolder = $scheduleService.GetFolder("\")
        $taskDefinition = $scheduleService.NewTask(0)
        $taskDefinition.Settings.StopIfGoingOnBatteries = $false
        $taskDefinition.Settings.DisallowStartIfOnBatteries = $false
        $taskDefinition.Principal.UserID = $Identity
        $taskDefinition.Principal.LogonType = 3
        $taskDefinition.Principal.RunLevel = 1
        $taskName = [guid]::NewGuid().Guid
        $taskAction = $taskDefinition.Actions.Create(0)
        $taskAction.WorkingDirectory = "%windir%\System32\WindowsPowerShell\v1.0\"
        $taskAction.Path = "powershell"
        $taskAction.Arguments = $argument
        $taskAction.HideAppWindow = $True

        Write-Verbose "Registering scheduled task $taskName"
        $registeredTask = $scheduleTaskFolder.RegisterTaskDefinition($taskName, $taskDefinition, 6, $Identity, $null, 3)
        Write-Verbose "Running scheduled task as $Identity"
        $scheduledTask = $registeredTask.Run($null)

        Write-Verbose "Connecting to named pipe server \\.\pipe\$pipename"
        $pipeclient.Connect($timeout)
        $writer = New-Object  IO.StreamWriter($pipeclient)
        $writer.AutoFlush = $true
        $writer.WriteLine($payload)
        $reader = New-Object IO.StreamReader($pipeclient)
        $output = ''
        while (($data = $reader.ReadLine()) -ne $null) {
            $output += $data + [Environment]::NewLine
        }
        Write-Output ([Management.Automation.PSSerializer]::Deserialize($output))

        $scheduledTaskInfo = $scheduleTaskFolder.GetTasks(1) | Where-Object Name -eq $scheduledTask.Name
        if ($scheduledTaskInfo.LastRunTime.Year -ne (Get-Date).Year) { 
            Write-Warning "Failed to execute scheduled task."
        }
    }
    catch { 
        Write-Error "Task execution failed. $_"
    }
    finally {
        if ($reader) {
            $reader.Dispose()
        }
        $pipeclient.Dispose()

        Write-Verbose "Unregistering scheduled task $($taskParameters.TaskName)"
        if ($scheduledTask) { 
            $scheduleTaskFolder.DeleteTask($scheduledTask.Name, 0) | Out-Null
        }
    }
}
