[PSCustomObject]@{
    Vendor  = ""
    Product = ""
    
    GetVersion = {
        param(
            [string]$Target,
            [hashtable]$Params
        )

        $ModuleName = "SNMP"

        if (-not (Get-Module -Name $ModuleName -ListAvailable)) {
            Write-Host "Module '$ModuleName' not found. Installing..." -ForegroundColor Yellow
            
            Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
            
            Write-Host "Installation complete." -ForegroundColor Green
        }

        Import-Module -Name $ModuleName

        $SnmpCommunity  = if ($Params.ContainsKey("community")) { $Params["community"] } else { "public" }
        $SnmpOID        = if ($Params.ContainsKey("oid")) { $Params["oid"] } else { "" }
        $Port           = if ($Params.ContainsKey("port")) { $Params["port"] } else { 161 }
        $Regex          = if ($Params.ContainsKey("regex")) { $Params["regex"] } else { ", revision WC.([^,]+)" }

        try {
            $data = (Get-SnmpData -IP $Target -Community $SnmpCommunity -OID $SnmpOID -Version V2 -TimeOut 30 -UDPPort $Port).Data

            if ($Regex -and $data) {
                if ($data -match $Regex) {
                    Write-host $matches
                    if ($matches.Count -gt 1) {
                        return $matches[1]
                    } else {
                        return $matches[0]
                    }
                } else {
                    return $null 
                }
            }

            return $data
        } catch {
            Write-Error "Failed to retrieve SNMP data: $_"
            return $null
        }
    }
}