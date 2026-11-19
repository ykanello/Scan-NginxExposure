
<#
.SYNOPSIS
    Scans a list of URLs for nginx + HTTP/2 (ngx_http_v2) exposure fingerprinting,
    using curl.exe as the HTTP/TLS engine (bypasses PS5.1 .NET TLS stack issues).
.EXAMPLE
    .\Scan-NginxExposure.ps1 -UrlListPath @{Path=".\bnl.txt";Region="BNL"}, @{Path=".\nordics.txt";Region="Nordics"}
#>

param(
    [Parameter(Mandatory = $true)]
    [hashtable[]] $UrlListPath,

    [string] $OutputCsv = ".\nginx_scan_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [int] $TimeoutSeconds = 10,

    # Never fall back to an unverified TLS connection (default: fall back, because this
    # tool only fingerprints headers and corporate TLS inspection breaks verification).
    [switch] $StrictTls,

    # Skip certificate validation from the start (curl -k) instead of only after a TLS failure.
    [switch] $SkipCertCheck
)

# ---- Sanity check: curl.exe must be available ----
$curlPath = Get-Command curl.exe -ErrorAction SilentlyContinue
if (-not $curlPath) {
    Write-Error "curl.exe not found on PATH. It ships with Windows 10 1803+/Server 2019+. Aborting."
    return
}

$userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ---- Build target list ----
$targets = foreach ($entry in $UrlListPath) {
    if (-not (Test-Path $entry.Path)) {
        Write-Warning "File not found: $($entry.Path) - skipping"
        continue
    }
    Get-Content $entry.Path | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') } | ForEach-Object {
        $u = $_.Trim()
        if ($u -notmatch '^https?://') { $u = "https://$u" }
        [pscustomobject]@{ Url = $u; Region = $entry.Region }
    }
}

if (-not $targets) {
    Write-Error "No URLs loaded. Check your input files."
    return
}

Write-Host "Loaded $($targets.Count) URLs. Scanning with curl.exe..." -ForegroundColor Cyan

# curl exit codes that mean "TLS handshake / certificate trust problem" (not a dead host)
$script:TlsExitCodes = @(35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91)

function Invoke-CurlScan {
    param([string]$Url, [int]$TimeoutSeconds, [string]$UserAgent, [switch]$Insecure)

    $headerFile = [System.IO.Path]::GetTempFileName()
    try {
        $wFormat = "{0}|{1}" -f '%{http_code}', '%{http_version}'
        $curlArgs = @(
            '-s', '-S', '-L', '--max-redirs', '5',
            '-o', 'NUL',
            '-D', $headerFile,
            '--http2',
            # schannel: do not fail when CRL/OCSP servers are unreachable (proxy/firewall)
            '--ssl-no-revoke',
            '-A', $UserAgent,
            '--max-time', $TimeoutSeconds,
            '-w', $wFormat
        )
        if ($Insecure) { $curlArgs += '-k' }
        $curlArgs += $Url

        # -S keeps -s quiet but still prints the error text; capture it instead of discarding it
        $out = & curl.exe @curlArgs 2>&1
        $exitCode = $LASTEXITCODE
        $stdout = ($out | Where-Object { $_ -is [string] -and $_ -match '^\d{3}\|[\d\.]+$' } | Select-Object -Last 1)
        $curlError = (($out | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } |
                        ForEach-Object { $_.ToString().Trim() }) -join ' ')
        $rawHeaders = if (Test-Path $headerFile) { Get-Content $headerFile -Raw } else { '' }

        $statusCode  = $null
        $httpVersion = $null
        if ($stdout -match '^(?<code>\d{3})\|(?<ver>[\d\.]+)$') {
            $statusCode  = $Matches['code']
            $httpVersion = $Matches['ver']
        }

        return [pscustomobject]@{
            ExitCode    = $exitCode
            StatusCode  = $statusCode
            HttpVersion = $httpVersion
            RawHeaders  = $rawHeaders
            CurlError   = $curlError
        }
    }
    finally {
        Remove-Item $headerFile -ErrorAction SilentlyContinue
    }
}

$results = foreach ($target in $targets) {

    $result = [ordered]@{
        Region               = $target.Region
        Url                  = $target.Url
        StatusCode           = $null
        ServerHeader         = $null
        NginxDetected        = $false
        NginxVersion         = $null
        FrontedByCdnWaf      = $false
        CdnWafGuess          = $null
        Http2Supported       = $false
        VulnerableCandidate  = $false
        DirectOriginExposure = $false
        Caveat               = $null
        TlsVerified          = $true
        Error                = $null
    }

    if ($SkipCertCheck) {
        $scan = Invoke-CurlScan -Url $target.Url -TimeoutSeconds $TimeoutSeconds -UserAgent $userAgent -Insecure
        $result.TlsVerified = $false
    } else {
        $scan = Invoke-CurlScan -Url $target.Url -TimeoutSeconds $TimeoutSeconds -UserAgent $userAgent
    }

    # TLS trust failure (TLS inspection proxy, missing CA, ...): retry once without verification.
    # Safe here because the scan only reads the Server header / negotiated HTTP version.
    if (-not $StrictTls -and -not $SkipCertCheck -and $scan.ExitCode -in $script:TlsExitCodes) {
        $firstError = $scan.CurlError
        $scan = Invoke-CurlScan -Url $target.Url -TimeoutSeconds $TimeoutSeconds -UserAgent $userAgent -Insecure
        $result.TlsVerified = $false
        if ($scan.ExitCode -eq 0 -and $scan.StatusCode) {
            $result.Caveat = "TLS certificate not verified (curl: $firstError). Server/HTTP2 data may come from a TLS-inspection proxy, not the origin."
        }
    }

    if ($scan.ExitCode -ne 0 -or -not $scan.StatusCode) {
        $result.Error = "curl exit code $($scan.ExitCode): $($scan.CurlError)"
        [pscustomobject]$result
        continue
    }

    $result.StatusCode = $scan.StatusCode

    # Headers can repeat across redirect hops - take values from the LAST response block
    $headerBlocks = $scan.RawHeaders -split "(?:\r?\n){2,}" | Where-Object { $_.Trim() }
    $lastBlock = $headerBlocks | Select-Object -Last 1

    $serverLine = ($lastBlock -split "`r?`n" | Where-Object { $_ -match '^Server:' } | Select-Object -Last 1)
    if ($serverLine) { $result.ServerHeader = ($serverLine -replace '^Server:\s*', '').Trim() }

    $cdnSignals = @()
    if ($lastBlock -match '(?im)^CF-RAY:')               { $cdnSignals += 'Cloudflare' }
    if ($result.ServerHeader -match 'cloudflare')         { $cdnSignals += 'Cloudflare' }
    if ($lastBlock -match '(?im)^X-Akamai-Transformed:')  { $cdnSignals += 'Akamai' }
    if ($lastBlock -match '(?im)^X-Amz-Cf-Id:')           { $cdnSignals += 'CloudFront' }
    if ($lastBlock -match '(?im)^X-Azure-Ref:')           { $cdnSignals += 'Azure Front Door' }
    if ($cdnSignals.Count -gt 0) {
        $result.FrontedByCdnWaf = $true
        $result.CdnWafGuess = ($cdnSignals | Select-Object -Unique) -join ', '
    }

    if ($result.ServerHeader -match 'nginx(?:/(?<ver>[\d\.]+))?') {
        $result.NginxDetected = $true
        if ($Matches['ver']) { $result.NginxVersion = $Matches['ver'] }
    }

    $result.Http2Supported = ($scan.HttpVersion -eq '2')

    $result.VulnerableCandidate  = ($result.NginxDetected -and $result.Http2Supported)
    $result.DirectOriginExposure = ($result.VulnerableCandidate -and -not $result.FrontedByCdnWaf)

    $tlsNote = $result.Caveat
    if ($result.VulnerableCandidate) {
        if ($result.FrontedByCdnWaf) {
            $result.Caveat = "Behind $($result.CdnWafGuess) - h2 negotiated at edge, origin not confirmed. WAF mitigates, does not fix - patch origin anyway."
        } else {
            $result.Caveat = "No CDN/WAF detected - direct-to-origin exposure, high priority."
        }
        if ($tlsNote) { $result.Caveat = "$($result.Caveat) $tlsNote" }
    }

    [pscustomobject]$result
}

# ---- Output ----
$results | Sort-Object Region, Url | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

$nginxOnly      = $results | Where-Object { $_.NginxDetected -and -not $_.Http2Supported }
$nginxPlusHttp2 = $results | Where-Object { $_.NginxDetected -and $_.Http2Supported }

Write-Host "`n=== Summary ===" -ForegroundColor Yellow
Write-Host "Total URLs scanned   : $($results.Count)"
Write-Host "Fronted by CDN/WAF   : $(($results | Where-Object { $_.FrontedByCdnWaf }).Count)"
Write-Host "Errors / unreachable : $(($results | Where-Object { $_.Error }).Count)"
Write-Host "TLS not verified     : $(($results | Where-Object { -not $_.TlsVerified }).Count) (scanned anyway; see Caveat/Error columns)"

if ($nginxOnly.Count -gt 0) {
    Write-Host "`n[NOTICE] nginx detected on $($nginxOnly.Count) host(s):" -ForegroundColor Yellow
    $nginxOnly | Format-Table Region, Url, ServerHeader, NginxVersion, FrontedByCdnWaf -AutoSize
}

if ($nginxPlusHttp2.Count -gt 0) {
    Write-Host "`n[NOTICE] nginx detected on $($nginxPlusHttp2.Count) host(s):" -ForegroundColor Red
    Write-Host "[NOTICE] of those, HTTP/2 also negotiated - in scope for the HTTP/2 RCE:" -ForegroundColor Red
    $nginxPlusHttp2 | Format-Table Region, Url, ServerHeader, NginxVersion, Http2Supported, FrontedByCdnWaf -AutoSize

    Write-Host "`nCaveat: most/all of these likely sit behind a WAF (Cloudflare etc.)." -ForegroundColor DarkYellow
    Write-Host "Where FrontedByCdnWaf=True, h2 negotiation is with the edge, not confirmed on origin." -ForegroundColor DarkYellow
    Write-Host "WAF mitigates, does not fix - patch origin regardless." -ForegroundColor DarkYellow

    $directOrigin = $nginxPlusHttp2 | Where-Object { $_.DirectOriginExposure }
    if ($directOrigin.Count -gt 0) {
        Write-Host "`n$($directOrigin.Count) host(s) NOT behind a detected CDN/WAF - direct-to-origin exposure:" -ForegroundColor Magenta
        $directOrigin | Format-Table Region, Url, ServerHeader, NginxVersion -AutoSize
    }
}

Write-Host "`nResults written to: $OutputCsv" -ForegroundColor Green
