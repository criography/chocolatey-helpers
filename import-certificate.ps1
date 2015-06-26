#


# ====================================================
# Import-Certificate
# ====================================================
# Function to import security certificates.
# NOTE: To get a list of available store names, run the following command:
# dir cert: | Select -Expand StoreNames
#
# Example Usages:
# Import-Certificate -CertFile "VeriSign_Expires-2028.08.01.cer" -StoreNames AuthRoot, Root -LocalMachine
# Import-Certificate -CertFile "VeriSign_Expires-2018.05.18.p12" -StoreNames AuthRoot -LocalMachine -CurrentUser -CertPassword Password -Verbose
# dir -Path C:\Certs -Filter *.cer | Import-Certificate -CertFile $_ -StoreNames AuthRoot, Root -LocalMachine -Verbose
#
# @src			http://poshcode.org/3518
#	@depends 	Powershell 2+
#
# @param    {string}    $CertFile    		Full path to .crt file
# @param    {list}    	$StoreNames   	Comma separated list of strings corresponding to Crtificate shops:
#																				SmartCardRoot | UserDS | AuthRoot | CA | Trust | Disallowed | My | 
#																				Root | TrustedPeople | TrustedPublisher
# @param 		{bool}			$LocalMachine		Using the local machine certificate store to import the certificate
# @param 		{bool}			$CurrentUser 		Using the current user certificate store to import the certificate
# @param    {string}    $CertPassword 	The password which may be used to protect the certificate file
# @param 		{bool}			$Verbose 				Spit out stuff         
# @return   {string}                    Full uninstall path (no flags)
# ====================================================

# Function to import security certificates.
# http://poshcode.org/3518
# NOTE: To get a list of available store names, run the following command:
# dir cert: | Select -Expand StoreNames
#


function Import-Certificate
{
	param
	(
		[IO.FileInfo] $CertFile = $(throw "Paramerter -CertFile [System.IO.FileInfo] is required."),
		[string[]] $StoreNames = $(throw "Paramerter -StoreNames [System.String] is required."),
		[switch] $LocalMachine,
		[switch] $CurrentUser,
		[string] $CertPassword,
		[switch] $Verbose
	)
	
	begin
	{
		[void][System.Reflection.Assembly]::LoadWithPartialName("System.Security")
	}
	
	process 
	{
        if ($Verbose)
		{
            $VerbosePreference = 'Continue'
        }
    
		if (-not $LocalMachine -and -not $CurrentUser)
		{
			Write-Warning "One or both of the following parameters are required: '-LocalMachine' '-CurrentUser'. Skipping certificate '$CertFile'."
		}

		try
		{
			if ($_)
            {
                $certfile = $_
            }
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certfile,$CertPassword
		}
		catch
		{
			Write-Error ("Error importing '$certfile': $_ .") -ErrorAction:Continue
		}
			
		if ($cert -and $LocalMachine)
		{
			$StoreScope = "LocalMachine"
			$StoreNames | ForEach-Object {
				$StoreName = $_
				if (Test-Path "cert:\$StoreScope\$StoreName")
				{
					try
					{
						$store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreScope
						$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
						$store.Add($cert)
						$store.Close()
						Write-Verbose "Successfully added '$certfile' to 'cert:\$StoreScope\$StoreName'."
					}
					catch
					{
						Write-Error ("Error adding '$certfile' to 'cert:\$StoreScope\$StoreName': $_ .") -ErrorAction:Continue
					}
				}
				else
				{
					Write-Warning "Certificate store '$StoreName' does not exist. Skipping..."
				}
			}
		}
		
		if ($cert -and $CurrentUser)
		{
			$StoreScope = "CurrentUser"
			$StoreNames | ForEach-Object {
				$StoreName = $_
				if (Test-Path "cert:\$StoreScope\$StoreName")
				{
					try
					{
						$store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreScope
						$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
						$store.Add($cert)
						$store.Close()
						Write-Verbose "Successfully added '$certfile' to 'cert:\$StoreScope\$StoreName'."
					}
					catch
					{
						Write-Error ("Error adding '$certfile' to 'cert:\$StoreScope\$StoreName': $_ .") -ErrorAction:Continue
					}
				}
				else
				{
					Write-Warning "Certificate store '$StoreName' does not exist. Skipping..."
				}
			}
		}
	}
	
	end
	{ }
}