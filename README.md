# PRTG NVD Vulnerability Sensor

**Note:** Readme has been creted with Gemini 3.1 Pro.

A modular, cross-platform PRTG Advanced Custom Sensor that dynamically checks your software versions against the National Vulnerability Database (NVD) to alert you of known CVEs. 

It uses a plugin-based architecture, allowing you to query different products using a single central script. The sensor outputs native PRTG JSON, automatically mapping CVE severity levels (Critical, High, Medium, Low) to PRTG channels with built-in warning and error thresholds.

---

## Installation

1. Copy the main script and the `Providers` folder to your PRTG Probe's Custom Sensors directory:
   `C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML`
2. Your folder structure must look exactly like this:
   ```text
   Custom Sensors\EXEXML\
   ├── Get-ProductCVEs.ps1
   └── Providers\
       ├── gitlab.ps1
       ├── snmpv2.ps1
       ├── static.ps1
       └── <custom_provider.ps1>
   ```
3. Make sure the .ps1 files are not being blocked by Windows (use `Unblock-File <filename>`).
---

## How It Works: Understanding CPEs

The National Vulnerability Database (NVD) uses a strict naming standard called **Common Platform Enumeration (CPE)** to track software. 

A CPE string looks like this:
`cpe:2.3:a:gitlab:gitlab:19.0.1:*:*:*:*:*:*:*`

* `cpe:2.3`: The CPE protocol version.
* `a`: The part type (`a` = application, `o` = operating system, `h` = hardware).
* `gitlab`: The **Vendor**.
* `gitlab`: The **Product**.
* `19.0.1`: The **Version**.
* `*`: Wildcards for minor updates, target software, architecture, etc.

When this sensor runs, the Provider module defines the Vendor, Product and fetches your current running Version, stitches the CPE string together, and then performs a NVD API lookup to get all CVEs matching this exact CPE string.

---

## Configuration in PRTG

1. Create a new **EXE/Script Advanced** sensor in PRTG.
2. Select `Check-ProductCVEs.ps1` from the executable dropdown.
3. In the **Parameters** field, define your arguments. 

**Example for GitLab:**
```text
-Provider "gitlab" -Target "%host" -NvdApiKey "YOUR_API_KEY" -ProviderParams '{"Token": "glpat-12345"}'
```

### Parameter Reference
| Parameter | Description |
| :--- | :--- |
| `-Provider` | The name of the `.ps1` file in the Providers folder (e.g., `gitlab`). |
| `-Target` | The IP or DNS name of the target server. Usually passed by PRTG as `%host`. |
| `-NvdApiKey` | (Optional but recommended) Your NIST API Key. Prevents rate-limiting (HTTP 403) from NVD. Get one for free at `nvd.nist.gov`. |
| `-Version` | The version of the CPE definition (default is `2.3`). |
| `-Type` | Part/Type used in the CPE string (default is `a`, other valid values may be `o` or `h`). |
| `-ProviderParams` | JSON string passed directly to the provider (e.g., `'{"community": "public", "oid": "1.3.6.1.2.1.1.1.0", "regex": ", revision WC.([^,]+)"}'`). Use PRTG placeholders for secrets like API tokens. |
---

## Provider Modules

### 1. Dynamic Providers (e.g., `gitlab.ps1`)
Dynamic providers contain logic to actively connect to the target software to fetch the exact version running at that moment.

**Example**
```powershell
-Provider "gitlab" -Target "%host" -ProviderParams '{"Token": "%scriptplaceholder1"}'
```

### 2. The `static.ps1` Provider
Not all software exposes its version cleanly over the network. 
* Some applications don't have REST APIs.
* Others intentionally mask their version numbers for security.
* Sometimes, strict firewalls prevent PRTG from querying the application directly.

For these edge cases, use the **`static.ps1`** provider. Instead of fetching the version dynamically, you manually define the version in the PRTG parameters.

**Example**
```powershell
-Provider "static" -Vendor "someVendor" -Product "coolProduct" -ProviderParams "Version=1.2.3"
```
*When you patch the software, do not forget to update the `Version=` parameter in the PRTG sensor settings.*