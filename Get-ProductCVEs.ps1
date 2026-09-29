<#
.SYNOPSIS
    PRTG Advanced Custom Sensor for querying the NVD API for product vulnerabilities.

.DESCRIPTION
    Dynamically executes a provider plugin using the Factory/Object pattern, 
    retrieves the product version, queries NVD API v2.0 via CPE matching, 
    and outputs PRTG-compliant JSON with dedicated severity channels.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$Provider,                        # Name of the provider file (e.g., "gitlab")
    [string]$Target = "",                     # Optional: Passed to provider; not necessary for static
    [string]$Vendor = "",                     # Optional: Overrides provider default vendor
    [string]$Product = "",                    # Optional: Overrides provider default product
    [string]$Type = "a",
    [string]$Version = "2.3",
    [string]$NvdApiKey = "",                  # Optional: NVD API key for higher rate limits
    [string]$ProviderParams = "",             # Optional: String of custom args (tokens, custom ports, etc.)
    [switch]$IgnoreSsl
)

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

if ($IgnoreSsl) {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        # macOS / Linux / PS Core 6+
        $PSDefaultParameterValues["Invoke-RestMethod:SkipCertificateCheck"] = $true
        $PSDefaultParameterValues["Invoke-WebRequest:SkipCertificateCheck"] = $true
    } else {
        # Windows PowerShell 5.1
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
} else {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }
}

function Out-PrtgJson {
    param (
        [int]$TotalCves = 0,
        [int]$Critical = 0,
        [int]$High = 0,
        [int]$Medium = 0,
        [int]$Low = 0,
        [float]$MaxCvss = 0.0,
        [string]$Message = "OK",
        [bool]$IsError = $false
    )

    if ($IsError) {
        $Output = @{
            prtg = @{
                error = 1
                text  = $Message
            }
        }
    } else {
        $Output = @{
            prtg = @{
                text   = $Message
                result = @(
                    @{ channel = "Total Vulnerabilities"; value = $TotalCves; unit = "Count" },
                    @{ channel = "Max CVSS Score"; value = $MaxCvss; float = 1; unit = "Custom"; customunit = "Score"; limitmaxwarning = 6.9; limitmaxerror = 8.9; limitmode = 1 },
                    @{ channel = "Critical CVEs (9.0+)"; value = $Critical; unit = "Count"; limitmaxerror = 0; limitmode = 1 },
                    @{ channel = "High CVEs (7.0-8.9)"; value = $High; unit = "Count"; limitmaxwarning = 0; limitmode = 1 },
                    @{ channel = "Medium CVEs"; value = $Medium; unit = "Count" },
                    @{ channel = "Low CVEs"; value = $Low; unit = "Count" }
                )
            }
        }
    }

    return ($Output | ConvertTo-Json -Depth 5 -Compress)
}

try {
    $ScriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
    if ([string]::IsNullOrEmpty($ScriptDir)) {
        $ScriptDir = $PWD.Path 
    }

    $ProviderFile = Join-Path -Path $ScriptDir -ChildPath "Providers\$Provider.ps1"
    
    if (-not (Test-Path -Path $ProviderFile)) { 
        throw "Provider plugin not found at: $ProviderFile" 
    }
    
    $Plugin = & $ProviderFile

    $ResolvedVendor  = if (-not [string]::IsNullOrWhiteSpace($Vendor))  { $Vendor }  else { $Plugin.Vendor }
    $ResolvedProduct = if (-not [string]::IsNullOrWhiteSpace($Product)) { $Product } else { $Plugin.Product }

    if ([string]::IsNullOrWhiteSpace($ResolvedVendor) -or [string]::IsNullOrWhiteSpace($ResolvedProduct)) {
        throw "Vendor and Product must be defined either in the provider or via script parameters."
    }

   $ParsedParams = @{}
    if (-not [string]::IsNullOrWhiteSpace($ProviderParams)) {
        # Convert from JSON and cast the custom object to a Hashtable
        $jsonObject = $ProviderParams | ConvertFrom-Json
        $jsonObject.psobject.properties | ForEach-Object {
            $ParsedParams[$_.Name] = $_.Value
        }
    }

    $CurrentVersion = & $Plugin.GetVersion $Target $ParsedParams
    Write-Host $CurrentVersion

    if ([string]::IsNullOrWhiteSpace($CurrentVersion)) {
        throw "Retrieved version from provider [$Provider] was empty."
    }

    $CpeString = "cpe:${Version}:${Type}:${ResolvedVendor}:${ResolvedProduct}:${CurrentVersion}:*:*:*:*:*:*:*"
    $NvdUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$CpeString&isVulnerable"

    $Headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($NvdApiKey)) {
        $Headers["apiKey"] = $NvdApiKey
    }

    $NvdResponse = Invoke-RestMethod -Uri $NvdUrl -Headers $Headers -Method Get -TimeoutSec 30 -ErrorAction Stop
    $Vulnerabilities = $NvdResponse.vulnerabilities

    if (-not $Vulnerabilities -or $Vulnerabilities.Count -eq 0) {
        $SuccessMsg = "$ResolvedProduct v$CurrentVersion is secure. No known CVEs found."
        $OutputJson = Out-PrtgJson -TotalCves 0 -MaxCvss 0.0 -Message $SuccessMsg
        Write-Output $OutputJson
        exit 0
    }

    $Total = $Vulnerabilities.Count
    $CritCount = 0; $HighCount = 0; $MedCount = 0; $LowCount = 0; $MaxScore = 0.0
    $CveList = @()

    foreach ($Vuln in $Vulnerabilities) {
        $CveList += $Vuln.cve.id
        
        $CvssScore = 0.0
        if ($Vuln.cve.metrics.cvssMetricV31) {
            $CvssScore = [float]$Vuln.cve.metrics.cvssMetricV31[0].cvssData.baseScore
        } elseif ($Vuln.cve.metrics.cvssMetricV30) {
            $CvssScore = [float]$Vuln.cve.metrics.cvssMetricV30[0].cvssData.baseScore
        } elseif ($Vuln.cve.metrics.cvssMetricV2) {
            $CvssScore = [float]$Vuln.cve.metrics.cvssMetricV2[0].cvssData.baseScore
        }

        if ($CvssScore -gt $MaxScore) { $MaxScore = $CvssScore }

        if ($CvssScore -ge 9.0)     { $CritCount++ }
        elseif ($CvssScore -ge 7.0) { $HighCount++ }
        elseif ($CvssScore -ge 4.0) { $MedCount++ }
        elseif ($CvssScore -gt 0.0) { $LowCount++ }
    }

    $CveString = $CveList -join ", "
    if ($CveString.Length -gt 150) { $CveString = $CveString.Substring(0, 147) + "..." }
    $FinalMsg = "$ResolvedProduct v$CurrentVersion has $Total CVE(s): $CveString"

    $OutputJson = Out-PrtgJson -TotalCves $Total `
                               -Critical $CritCount `
                               -High $HighCount `
                               -Medium $MedCount `
                               -Low $LowCount `
                               -MaxCvss $MaxScore `
                               -Message $FinalMsg

    Write-Output $OutputJson
    exit 0
}
catch {
    $LineNumber = 0
    $LineNumber = $_.InvocationInfo.ScriptLineNumber
    $ErrorMsg = $_.Exception.Message
    Write-Output (Out-PrtgJson -IsError $true -Message "Error at Line ${LineNumber}: ${ErrorMsg}")
    exit 0
}