function Get-UnfilteredEgress
{
<#
.SYNOPSIS
    Identify outbound TCP flow authorized regarding to egress filtering.

    Author: Timothée MENOCHET (@synetis)

.DESCRIPTION
    Get-UnfilteredEgress sends HTTP requests within a TCP port range in order to identify outbound TCP flow authorized regarding to egress filtering.

.PARAMETER Begin
    Specify the first port number of the range.

.PARAMETER End
    Specify the last port number of the range.

.PARAMETER ProxyHost
    Specify the hostname of the corporate proxy, if any.

.PARAMETER ProxyPort
    Specify the port number of the corporate proxy, if any.

.PARAMETER ProxyUser
    Specify the username for authentication within the corporate proxy, if required.

.PARAMETER ProxyPass
    Specify the password for authentication within the corporate proxy, if required.

.EXAMPLE
    PS C:\> Get-UnfilteredEgress -Begin 8000 -End 8080

.EXAMPLE
    PS C:\> Get-UnfilteredEgress -ProxyHost PROXY.ADATUM.CORP -ProxyPort 3128 -ProxyUser john.doe -ProxyPass P@ssw0rd
#>

	Param (
		[ValidateNotNullOrEmpty()]
		[Int]
		$Begin = 1,

		[ValidateNotNullOrEmpty()]
		[Int]
		$End = 1024,

		[ValidateNotNullOrEmpty()]
		[String]
		$ProxyHost,
		
		[ValidateNotNullOrEmpty()]
		[Int]
		$ProxyPort,
		
		[ValidateNotNullOrEmpty()]
		[String]
		$ProxyUser,
		
		[ValidateNotNullOrEmpty()]
		[String]
		$ProxyPass
	)

	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	$client = New-Object Net.WebClient;

	If ($ProxyHost -And $ProxyPort) {
		$client.Proxy =  New-Object Net.WebProxy($ProxyHost, $ProxyPort);
	}
	Else {
		$client.Proxy = [Net.WebRequest]::GetSystemWebProxy();
	}
	If ($ProxyUser -And $ProxyPass) {
		$client.Proxy.Credentials = New-Object Net.NetworkCredential($ProxyUser, $ProxyPass);
	}
	Else {
		$client.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials;
	}

	$Begin..$End | % {
		$Port = $_;
		Try {
			$x = $client.DownloadString('http://portquiz.net:' + $Port);
			echo "[+] TCP/$Port is unfiltered!";
		} Catch [Net.WebException] {
			# Handle HTTP 400 error when querying port 443
			echo "[+] TCP/$Port is unfiltered!";
		} Catch { 
			echo "[-] TCP/$Port is filtered.";
		}
	}
}