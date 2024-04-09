function Invoke-DcomExec {
<#
.SYNOPSIS
    Invoke PowerShell commands on a remote computer via DCOM.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-DcomExec runs PowerShell script block on remote computers through various DCOM methods and retrieves output via a named pipe.

.PARAMETER ScriptBlock
    Specifies the PowerShell script block to run.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Method
    Specifies the execution method to use, defaults to MMC20.Application.

.EXAMPLE
    PS C:\> Invoke-PowerExec -ComputerName SRV.ADATUM.CORP -ScriptBlock {Write-Output "$Env:COMPUTERNAME ($Env:USERDOMAIN\$Env:USERNAME)"} -Method ShellWindows
#>
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet("MMC20.Application", "ShellWindows", "ShellBrowserWindow")]
        [String]
        $Method = "MMC20.Application"
    )

    Begin {
        switch ($Method) {
            'MMC20.Application' {
                $clsid = '49B2791A-B1AE-4C90-9B8E-E860BA07F889'
            }
            'ShellWindows' {
                $clsid = '9BA05972-F6A8-11CF-A442-00A0C90A8F39'
            }
            'ShellBrowserWindow' {
                $clsid = 'C08AFD90-F2A1-11D1-8455-00A0C91F3880'
            }
        }

        # Init named pipe client
        $pipeTimeout = 10000 # 10s
        $pipeName = [guid]::NewGuid().Guid
        $pipeClient = New-Object IO.Pipes.NamedPipeClientStream($ComputerName, $pipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Impersonation)

        # Build loader
        $loader = ''
        $loader += '$s = new-object IO.Pipes.NamedPipeServerStream(''' + $pipeName + ''', 3); '
        $loader += '$s.WaitForConnection(); '
        $loader += '$r = new-object IO.StreamReader $s; '
        $loader += '$x = ''''; '
        $loader += 'while (($y=$r.ReadLine()) -ne ''''){$x+=$y+[Environment]::NewLine}; '
        $loader += '$z = [ScriptBlock]::Create($x); '
        $loader += '& $z'
        $arguments = '/c powershell -NoP -NonI -C "' + $loader + '"'
        $command = '%COMSPEC%'

        # Build payload
        $script = ''
        $script += '[ScriptBlock]$scriptBlock = {' + $ScriptBlock.Ast.Extent.Text + '}' + [Environment]::NewLine -replace '{{','{' -replace '}}','}'
        $script += '$output = [Management.Automation.PSSerializer]::Serialize((& $scriptBlock *>&1))' + [Environment]::NewLine
        $script += '$encOutput = [char[]]$output' + [Environment]::NewLine
        $script += '$writer = [IO.StreamWriter]::new($s)' + [Environment]::NewLine
        $script += '$writer.AutoFlush = $true' + [Environment]::NewLine
        $script += '$writer.WriteLine($encOutput)' + [Environment]::NewLine
        $script += '$writer.Dispose()' + [Environment]::NewLine
        $script += '$r.Dispose()' + [Environment]::NewLine
        $script += '$s.Dispose()' + [Environment]::NewLine
        $script = $script -creplace '(?m)^\s*\r?\n',''
        $payload = [char[]] $script
    }

    Process {
        Write-Verbose "Creating COM instance of $Method ($clsid)"
        try {
            $com = [Type]::GetTypeFromCLSID($clsid, $ComputerName)
            $obj = [Activator]::CreateInstance($com)
        }
        catch {
            Write-Error "Failed to create COM instance."
            break
        }

        Write-Verbose "Running command: $command $arguments"
        switch ($Method) {
            'MMC20.Application' {
                $obj.Document.ActiveView.ExecuteShellCommand('%COMSPEC%', $null, $arguments, '7')
            }
            'ShellWindows' {
                $item = $obj.Item()
                $item.Document.Application.ShellExecute('cmd.exe', $arguments, "C:\Windows\System32", $null, 0)
            }
            'ShellBrowserWindow' {
                $obj.Document.Application.ShellExecute('cmd.exe', $arguments, "C:\Windows\System32", $null, 0)
            }
        }

        Write-Verbose "Connecting to named pipe server \\$ComputerName\pipe\$pipeName"
        $pipeClient.Connect($pipeTimeout)
        $writer = New-Object  IO.StreamWriter($pipeClient)
        $writer.AutoFlush = $true
        $writer.WriteLine($payload)
        $reader = new-object IO.StreamReader($pipeClient)
        $output = ''
        while (($data = $reader.ReadLine()) -ne $null) {
            $output += $data + [Environment]::NewLine
        }
        Write-Output ([Management.Automation.PSSerializer]::Deserialize($output))
    }

    End {
        $reader.Dispose()
        $pipeClient.Dispose()
    }
}
