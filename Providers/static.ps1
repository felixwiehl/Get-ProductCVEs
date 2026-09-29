[PSCustomObject]@{
    Vendor  = ""
    Product = ""
    
    GetVersion = {
        param(
            [string]$Target,
            [hashtable]$Params
        )

        if ($Params.ContainsKey("Version")) {
            $StaticVersion = $Params["Version"]
            
            return $StaticVersion.Trim()
        }

        throw "Static version not provided. Please add '{""Version"": ""X.X.X""}' to your ProviderParams."
    }
}