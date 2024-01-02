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

    # Init variables
    $timeout = 10000 # 10s
    $pipename = [guid]::NewGuid().Guid
    $Global:output = $null

    # Build loader
    $loader = ''
    $loader += '$c = New-Object IO.Pipes.NamedPipeClientStream(''.'', ''' + $pipename + ''', [IO.Pipes.PipeDirection]::InOut); '
    $loader += '$c.Connect(' + $timeout + '); '
    $loader += '$r = New-Object IO.StreamReader $c; '
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
    $script += '$writer = [IO.StreamWriter]::new($c)' + [Environment]::NewLine
    $script += '$writer.AutoFlush = $true' + [Environment]::NewLine
    $script += '$writer.WriteLine($encOutput)' + [Environment]::NewLine
    $script += '$writer.Dispose()' + [Environment]::NewLine
    $script += '$r.Dispose()' + [Environment]::NewLine
    $script += '$c.Dispose()' + [Environment]::NewLine
    $script = $script -creplace '(?m)^\s*\r?\n',''
    $payload = [char[]] $script

    # Create named pipe server
    try {
        $accessRule = New-Object IO.Pipes.PipeAccessRule("Everyone", "FullControl", "Allow")
        $pipeSecurity = New-Object IO.Pipes.PipeSecurity
        $pipeSecurity.AddAccessRule($accessRule)
        $pipeServer = New-Object IO.Pipes.NamedPipeServerStream($pipename, [IO.Pipes.PipeDirection]::InOut, 1, [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous, 32768, 32768, $pipeSecurity)
        $serverCallback = [AsyncCallback] {
            param([IAsyncResult] $iar)
            Write-Verbose "Client connected to named pipe server \\.\pipe\$pipename"
            $pipeServer.EndWaitForConnection($iar)
            Write-Verbose "Delivering payload"
            $writer = New-Object IO.StreamWriter($pipeServer)
            $writer.AutoFlush = $true
            $writer.WriteLine($payload)
            Write-Verbose "Getting execution output"
            $reader = New-Object IO.StreamReader($pipeServer)
            $output = ''
            while (($data = $reader.ReadLine()) -ne $null) {
                $output += $data + [Environment]::NewLine
            }
            $Global:output = ([Management.Automation.PSSerializer]::Deserialize($output))
            $reader.Dispose()
        }
        $runspacedDelegate = [RunspacedDelegateFactory]::NewRunspacedDelegate($serverCallback, [Runspace]::DefaultRunspace)
        $job = $pipeServer.BeginWaitForConnection($runspacedDelegate, $null)
    }
    catch {
        if ($pipeServer) {
            $pipeServer.Close()
            $pipeServer.Dispose()
        }
        Write-Error "Pipe named server failed to start. $_" -ErrorAction Stop
    }

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
        do {
            $scheduledTaskInfo = $scheduleTaskFolder.GetTasks(1) | Where-Object Name -eq $scheduledTask.Name; Start-Sleep -Milliseconds 100
        }
        while ($scheduledTaskInfo.State -eq 3 -and $scheduledTaskInfo.LastTaskResult -eq 267045)
        do {
            $scheduledTaskInfo = $scheduleTaskFolder.GetTasks(1) | Where-Object Name -eq $scheduledTask.Name; Start-Sleep -Milliseconds 100
        }
        while ($scheduledTaskInfo.State -eq 4)
        if ($scheduledTaskInfo.LastRunTime.Year -ne (Get-Date).Year) { 
            Write-Warning "Failed to execute scheduled task."
        }
    }
    catch { 
        Write-Error "Task execution failed. $_"
    }
    finally {
        Write-Verbose "Unregistering scheduled task $($taskParameters.TaskName)"
        if ($scheduledTask) { 
            $scheduleTaskFolder.DeleteTask($scheduledTask.Name, 0) | Out-Null
        }
    }

    $pipeServer.Close()
    $pipeServer.Dispose()
    Write-Output ($Global:output)
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Management.Automation.Runspaces;
public class RunspacedDelegateFactory {
    public static Delegate NewRunspacedDelegate(Delegate _delegate, Runspace runspace) {
        Action setRunspace = () => Runspace.DefaultRunspace = runspace;
        return ConcatActionToDelegate(setRunspace, _delegate);
    }
    private static Expression ExpressionInvoke(Delegate _delegate, params Expression[] arguments) {
        var invokeMethod = _delegate.GetType().GetMethod("Invoke");
        return Expression.Call(Expression.Constant(_delegate), invokeMethod, arguments);
    }
    public static Delegate ConcatActionToDelegate(Action a, Delegate d) {
        var parameters = d.GetType().GetMethod("Invoke").GetParameters().Select(p => Expression.Parameter(p.ParameterType, p.Name)).ToArray();
        Expression body = Expression.Block(ExpressionInvoke(a), ExpressionInvoke(d, parameters));
        var lambda = Expression.Lambda(d.GetType(), body, parameters);
        var compiled = lambda.Compile();
        return compiled;
    }
}
'@
