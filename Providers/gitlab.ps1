[PSCustomObject]@{
    Vendor  = "gitlab"
    Product = "gitlab"
    
    GetVersion = {
        param(
            [string]$Target,
            [hashtable]$Params
        )

        $ApiToken = if ($Params.ContainsKey("Token")) { $Params["Token"] } else { "" }
        $UseHttps = if ($Params.ContainsKey("UseHttps")) { [bool]$Params["UseHttps"] } else { $true }
        $Port     = if ($Params.ContainsKey("Port")) { ":$($Params['Port'])" } else { "" }
        
        $Scheme = if ($UseHttps) { "https" } else { "http" }
        $Uri    = "${Scheme}://${Target}${Port}/api/v4/version"

        $Headers = @{}
        if (-not [string]::IsNullOrWhiteSpace($ApiToken)) {
            $Headers["PRIVATE-TOKEN"] = $ApiToken
        }

        $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -TimeoutSec 15 -ErrorAction Stop

        # Remove edition suffixes like -ee or -ce
        return ($Response.version -replace '-ee$|-ce$', '')
    }
}