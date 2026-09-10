[PSCustomObject]@{
    Vendor  = "progress_software"
    Product = "ws_ftp_server"
    
    GetVersion = {
        param(
            [string]$Target,
            [hashtable]$Params
        )

        if ($Params.ContainsKey("Version")) {
            $StaticVersion = $Params["Version"]
            
            return ($StaticVersion -replace '^v', '').Trim()
        }

        throw "Static version not provided. Please add 'Version=X.X.X' to your ProviderParams."
    }
}