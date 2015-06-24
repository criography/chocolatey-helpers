# ====================================================
# GetMenuStartPath
# ====================================================
# Grabs Menu Start location from registry.
#
# @return   {string}    Menu Start path
# ====================================================

Function GetMenuStartPath(){
	return (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."Start Menu"
}







# ====================================================
# GetUninstallString
# ====================================================
# Searches Registry for the uninstall string
#
# @param    {string}    $programName    Full program name, as its referred to in registry
# @return   {string}                    Full uninstall path (no flags)
# ====================================================

Function GetUninstallString([string]$programName){

  # establish all possible locations for uninstaller to be stored
  $local_key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
  $machine_key32 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
  $machine_key64 = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  $reg_locations = @()

  if(Test-Path "$local_key"){
    $reg_locations += "$local_key\*"
  }

  if(Test-Path "$machine_key32"){
    $reg_locations += "$machine_key32\*"
  }

  if( ((Get-WmiObject Win32_Processor).AddressWidth -eq 64) -and (Test-Path "$machine_key64") ) {
    $reg_locations += "$machine_key64\*"
  }

  # find and return the actual uninstaller path
  return (Get-ItemProperty -Path $reg_locations | ?{ $_.DisplayName -match $programName }).UninstallString
}






# ====================================================
# GetBinRoot
# ====================================================
# Negotiates BinRoot path
#
# @return   {string}    Full binroot path
# ====================================================

Function GetBinRoot(){

  $path = 'C:\tools'

  if($env:ChocolateyBinRoot -ne $null){
		$path = $env:ChocolateyBinRoot
  }

  return $path
}