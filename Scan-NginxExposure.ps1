
<#
.SYNOPSIS
    Scans a list of URLs for nginx + HTTP/2 (ngx_http_v2) exposure fingerprinting,
    using curl.exe as the HTTP/TLS engine (bypasses PS5.1 .NET TLS stack issues).
.EXAMPLE
    .\Scan-NginxExposure.ps1 -UrlListPath @{Path=".\bnl.txt";Region="BNL"}, @{Path=".\nordics.txt";Region="Nordics"}
#>

[CmdletBinding(DefaultParameterSetName = 'Scan')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Scan')]
    [hashtable[]] $UrlListPath,

    # Self-test of the HTTP/2 (ALPN) probe against one host, e.g. -TestAlpnHost nginx.org
    [Parameter(Mandatory = $true, ParameterSetName = 'Probe')]
    [string] $TestAlpnHost,

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

# ---- Does this curl.exe support HTTP/2? (many Windows builds lack nghttp2 -> "--http2" is a fatal error) ----
$curlHasHttp2 = [bool]((& curl.exe -V 2>$null) -match '(?i)\bHTTP2\b')

# ---- ALPN probe: negotiates TLS offering h2 + http/1.1 and reports what the server picks ----
# Needs .NET 5+ (PowerShell 7). Returns $true / $false, or $null when it cannot be tested.
$alpnAvailable = [bool]('System.Net.Security.SslClientAuthenticationOptions' -as [type]) -and
                 [bool]('System.Net.Security.SslApplicationProtocol' -as [type])

function Test-H2Alpn {
    param([string]$HostName, [int]$Port = 443, [int]$TimeoutSeconds = 10)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) { return $null }
        $client.EndConnect($iar)
        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false)
        $opts = New-Object System.Net.Security.SslClientAuthenticationOptions
        $opts.TargetHost = $HostName
        $opts.ApplicationProtocols = New-Object 'System.Collections.Generic.List[System.Net.Security.SslApplicationProtocol]'
        $opts.ApplicationProtocols.Add([System.Net.Security.SslApplicationProtocol]::Http2)
        $opts.ApplicationProtocols.Add([System.Net.Security.SslApplicationProtocol]::Http11)
        $opts.RemoteCertificateValidationCallback = [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
        $ssl.AuthenticateAsClient($opts)
        return ($ssl.NegotiatedApplicationProtocol -eq [System.Net.Security.SslApplicationProtocol]::Http2)
    }
    catch { return $null }
    finally { $client.Close() }
}

# ---- Windows PowerShell 5.1 fallback: tiny Schannel (native Windows TLS) client, compiled with Add-Type ----
$schannelSource = @'
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

// Minimal Schannel TLS client handshake that only reports which ALPN protocol the server selects.
// Works on stock Windows (Windows PowerShell 5.1 / .NET Framework). Certificates are NOT validated.
public static class SchannelAlpn
{
    [StructLayout(LayoutKind.Sequential)]
    struct SecBuffer { public uint cbBuffer; public uint BufferType; public IntPtr pvBuffer; }

    [StructLayout(LayoutKind.Sequential)]
    struct SecBufferDesc { public uint ulVersion; public uint cBuffers; public IntPtr pBuffers; }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, EntryPoint = "AcquireCredentialsHandleW")]
    static extern int AcquireCredentialsHandle(string pszPrincipal, string pszPackage, uint fCredentialUse,
        IntPtr pvLogonId, IntPtr pAuthData, IntPtr pGetKeyFn, IntPtr pvGetKeyArgument, IntPtr phCredential, out long ptsExpiry);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, EntryPoint = "InitializeSecurityContextW")]
    static extern int InitializeSecurityContext(IntPtr phCredential, IntPtr phContext, string pszTargetName,
        uint fContextReq, uint Reserved1, uint TargetDataRep, IntPtr pInput, uint Reserved2,
        IntPtr phNewContext, IntPtr pOutput, out uint pfContextAttr, out long ptsExpiry);

    [DllImport("secur32.dll", EntryPoint = "QueryContextAttributesW")]
    static extern int QueryContextAttributes(IntPtr phContext, uint ulAttribute, IntPtr pBuffer);

    [DllImport("secur32.dll")] static extern int DeleteSecurityContext(IntPtr phContext);
    [DllImport("secur32.dll")] static extern int FreeCredentialsHandle(IntPtr phCredential);
    [DllImport("secur32.dll")] static extern int FreeContextBuffer(IntPtr pvContextBuffer);

    const uint SECBUFFER_EMPTY = 0, SECBUFFER_TOKEN = 2, SECBUFFER_EXTRA = 5, SECBUFFER_APPLICATION_PROTOCOLS = 18;
    const uint ISC_FLAGS = 0x4 | 0x8 | 0x10 | 0x100 | 0x4000 | 0x8000 | 0x80000;
    // REPLAY_DETECT | SEQUENCE_DETECT | CONFIDENTIALITY | ALLOCATE_MEMORY | EXTENDED_ERROR | STREAM | MANUAL_CRED_VALIDATION
    const int SEC_E_OK = 0;
    const int SEC_I_CONTINUE_NEEDED = 0x00090312;
    const int SEC_E_INCOMPLETE_MESSAGE = unchecked((int)0x80090318);
    const uint SECPKG_ATTR_APPLICATION_PROTOCOL = 35;

    static IntPtr BuildDesc(SecBuffer[] bufs)
    {
        int sz = Marshal.SizeOf(typeof(SecBuffer));
        IntPtr arr = Marshal.AllocHGlobal(sz * bufs.Length);
        for (int i = 0; i < bufs.Length; i++)
            Marshal.StructureToPtr(bufs[i], new IntPtr(arr.ToInt64() + (long)i * sz), false);
        SecBufferDesc d = new SecBufferDesc();
        d.ulVersion = 0; d.cBuffers = (uint)bufs.Length; d.pBuffers = arr;
        IntPtr pd = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecBufferDesc)));
        Marshal.StructureToPtr(d, pd, false);
        return pd;
    }

    static SecBuffer ReadBuf(IntPtr desc, int index)
    {
        SecBufferDesc d = (SecBufferDesc)Marshal.PtrToStructure(desc, typeof(SecBufferDesc));
        int sz = Marshal.SizeOf(typeof(SecBuffer));
        return (SecBuffer)Marshal.PtrToStructure(new IntPtr(d.pBuffers.ToInt64() + (long)index * sz), typeof(SecBuffer));
    }

    static void FreeDesc(IntPtr desc)
    {
        SecBufferDesc d = (SecBufferDesc)Marshal.PtrToStructure(desc, typeof(SecBufferDesc));
        Marshal.FreeHGlobal(d.pBuffers);
        Marshal.FreeHGlobal(desc);
    }

    static byte[] BuildAlpnBlob()
    {
        byte[] list = new byte[] { 2, (byte)'h', (byte)'2', 8, (byte)'h', (byte)'t', (byte)'t', (byte)'p', (byte)'/', (byte)'1', (byte)'.', (byte)'1' };
        List<byte> b = new List<byte>();
        b.AddRange(BitConverter.GetBytes((uint)(4 + 2 + list.Length))); // ProtocolListsSize
        b.AddRange(BitConverter.GetBytes((uint)2));                      // SecApplicationProtocolNegotiationExt_ALPN
        b.AddRange(BitConverter.GetBytes((ushort)list.Length));          // ProtocolListSize
        b.AddRange(list);
        return b.ToArray();
    }

    static int ReadMore(NetworkStream ns, List<byte> pending)
    {
        byte[] buf = new byte[16384];
        int n = ns.Read(buf, 0, buf.Length);
        if (n <= 0) throw new Exception("connection closed during TLS handshake");
        for (int i = 0; i < n; i++) pending.Add(buf[i]);
        return n;
    }

    // Returns the negotiated ALPN protocol ("h2", "http/1.1"), "" when the server selected none,
    // or "ERROR: <reason>" when the handshake failed.
    public static string Probe(string host, int port, int timeoutMs)
    {
        TcpClient client = new TcpClient();
        IntPtr cred = IntPtr.Zero, ctx = IntPtr.Zero;
        bool haveCred = false, haveCtx = false;
        try
        {
            IAsyncResult iar = client.BeginConnect(host, port, null, null);
            if (!iar.AsyncWaitHandle.WaitOne(timeoutMs)) return "ERROR: connect timeout";
            client.EndConnect(iar);
            client.ReceiveTimeout = timeoutMs; client.SendTimeout = timeoutMs;
            NetworkStream ns = client.GetStream();

            cred = Marshal.AllocHGlobal(IntPtr.Size * 2);
            ctx = Marshal.AllocHGlobal(IntPtr.Size * 2);
            for (int z = 0; z < IntPtr.Size * 2; z++) { Marshal.WriteByte(cred, z, 0); Marshal.WriteByte(ctx, z, 0); }
            long exp;
            int rc = AcquireCredentialsHandle(null, "Microsoft Unified Security Protocol Provider", 2,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, cred, out exp);
            if (rc != 0) return "ERROR: AcquireCredentialsHandle 0x" + rc.ToString("X8");
            haveCred = true;

            List<byte> pending = new List<byte>();
            bool first = true;
            for (int round = 0; round < 20; round++)
            {
                SecBuffer[] inb;
                IntPtr tokMem = IntPtr.Zero, alpnMem = IntPtr.Zero;
                IntPtr inDesc = IntPtr.Zero;
                if (first)
                {
                    byte[] blob = BuildAlpnBlob();
                    alpnMem = Marshal.AllocHGlobal(blob.Length);
                    Marshal.Copy(blob, 0, alpnMem, blob.Length);
                    SecBuffer a = new SecBuffer();
                    a.cbBuffer = (uint)blob.Length; a.BufferType = SECBUFFER_APPLICATION_PROTOCOLS; a.pvBuffer = alpnMem;
                    inb = new SecBuffer[] { a };
                }
                else
                {
                    byte[] data = pending.ToArray();
                    tokMem = Marshal.AllocHGlobal(data.Length);
                    Marshal.Copy(data, 0, tokMem, data.Length);
                    SecBuffer t = new SecBuffer();
                    t.cbBuffer = (uint)data.Length; t.BufferType = SECBUFFER_TOKEN; t.pvBuffer = tokMem;
                    SecBuffer e = new SecBuffer();
                    e.cbBuffer = 0; e.BufferType = SECBUFFER_EMPTY; e.pvBuffer = IntPtr.Zero;
                    inb = new SecBuffer[] { t, e };
                }
                inDesc = BuildDesc(inb);
                SecBuffer o = new SecBuffer();
                o.cbBuffer = 0; o.BufferType = SECBUFFER_TOKEN; o.pvBuffer = IntPtr.Zero;
                IntPtr outDesc = BuildDesc(new SecBuffer[] { o });

                uint attrs; long exp2;
                rc = InitializeSecurityContext(cred, first ? IntPtr.Zero : ctx, host, ISC_FLAGS, 0, 0,
                    inDesc, 0, ctx, outDesc, out attrs, out exp2);
                if (first && (rc == SEC_E_OK || rc == SEC_I_CONTINUE_NEEDED)) haveCtx = true;

                uint extra = 0;
                if (!first)
                {
                    SecBuffer e1 = ReadBuf(inDesc, 1);
                    if (e1.BufferType == SECBUFFER_EXTRA) extra = e1.cbBuffer;
                }
                SecBuffer ob = ReadBuf(outDesc, 0);
                byte[] outTok = null;
                if (ob.pvBuffer != IntPtr.Zero)
                {
                    if (ob.cbBuffer > 0)
                    {
                        outTok = new byte[ob.cbBuffer];
                        Marshal.Copy(ob.pvBuffer, outTok, 0, (int)ob.cbBuffer);
                    }
                    FreeContextBuffer(ob.pvBuffer);
                }
                FreeDesc(inDesc); FreeDesc(outDesc);
                if (alpnMem != IntPtr.Zero) Marshal.FreeHGlobal(alpnMem);
                if (tokMem != IntPtr.Zero) Marshal.FreeHGlobal(tokMem);

                if (outTok != null) ns.Write(outTok, 0, outTok.Length);

                if (rc == SEC_E_OK) break;
                if (rc == SEC_I_CONTINUE_NEEDED)
                {
                    if (!first && extra > 0 && extra <= pending.Count)
                        pending.RemoveRange(0, pending.Count - (int)extra);
                    else
                        pending.Clear();
                    if (pending.Count == 0) ReadMore(ns, pending);
                }
                else if (rc == SEC_E_INCOMPLETE_MESSAGE)
                {
                    ReadMore(ns, pending);
                }
                else
                {
                    return "ERROR: InitializeSecurityContext 0x" + rc.ToString("X8");
                }
                first = false;
                if (round == 19) return "ERROR: handshake did not complete";
            }

            IntPtr q = Marshal.AllocHGlobal(512);
            try
            {
                for (int i = 0; i < 512; i++) Marshal.WriteByte(q, i, 0);
                rc = QueryContextAttributes(ctx, SECPKG_ATTR_APPLICATION_PROTOCOL, q);
                if (rc != 0) return "ERROR: QueryContextAttributes 0x" + rc.ToString("X8");
                int status = Marshal.ReadInt32(q, 0);
                int len = Marshal.ReadByte(q, 8);
                if (status != 1 || len == 0) return "";
                byte[] id = new byte[len];
                Marshal.Copy(new IntPtr(q.ToInt64() + 9), id, 0, len);
                return Encoding.ASCII.GetString(id);
            }
            finally { Marshal.FreeHGlobal(q); }
        }
        catch (Exception ex)
        {
            return "ERROR: " + ex.Message;
        }
        finally
        {
            if (haveCtx) DeleteSecurityContext(ctx);
            if (haveCred) FreeCredentialsHandle(cred);
            if (ctx != IntPtr.Zero) Marshal.FreeHGlobal(ctx);
            if (cred != IntPtr.Zero) Marshal.FreeHGlobal(cred);
            client.Close();
        }
    }
}
'@

function Test-H2Schannel {
    param([string]$HostName, [int]$Port = 443, [int]$TimeoutSeconds = 10)
    $r = [SchannelAlpn]::Probe($HostName, $Port, $TimeoutSeconds * 1000)
    $script:H2Detail = $null
    if ($r -like 'ERROR:*') { $script:H2Detail = $r; return $null }
    return ($r -eq 'h2')
}

$schannelAvailable = $false
$script:H2Detail = $null
if ((-not $curlHasHttp2 -and -not $alpnAvailable) -or $PSCmdlet.ParameterSetName -eq 'Probe') {
    try {
        Add-Type -TypeDefinition $schannelSource -ErrorAction Stop
        $schannelAvailable = $true
    }
    catch {
        $schannelError = $_.Exception.Message
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Probe') {
    Write-Host "curl.exe supports HTTP/2 : $curlHasHttp2"
    Write-Host "SslStream ALPN (PS7)     : $alpnAvailable"
    Write-Host "Schannel probe compiled  : $schannelAvailable $schannelError"
    if ($schannelAvailable) {
        $r = [SchannelAlpn]::Probe($TestAlpnHost, 443, $TimeoutSeconds * 1000)
        Write-Host "Schannel ALPN result for $TestAlpnHost : '$r'   (h2 = HTTP/2, http/1.1 = no HTTP/2, empty = no ALPN, ERROR: = probe failed)"
    }
    return
}

if (-not $curlHasHttp2) {
    if ($alpnAvailable) {
        Write-Warning "This curl.exe has no HTTP/2 support - HTTP/2 will be tested with a TLS ALPN probe (SslStream) instead."
    } elseif ($schannelAvailable) {
        Write-Warning "This curl.exe has no HTTP/2 support - HTTP/2 will be tested with a built-in Schannel ALPN probe instead."
    } else {
        Write-Warning "This curl.exe has no HTTP/2 support and the Schannel probe could not be compiled ($schannelError): Http2Supported will be 'Unknown'."
    }
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
        $wFormat = "{0}|{1}|{2}" -f '%{http_code}', '%{http_version}', '%{url_effective}'
        $curlArgs = @(
            '-s', '-S', '-L', '--max-redirs', '5',
            '-o', 'NUL',
            '-D', $headerFile,
            # schannel: do not fail when CRL/OCSP servers are unreachable (proxy/firewall)
            '--ssl-no-revoke',
            '-A', $UserAgent,
            '--max-time', $TimeoutSeconds,
            '-w', $wFormat
        )
        if ($script:curlHasHttp2) { $curlArgs += '--http2' }
        if ($Insecure) { $curlArgs += '-k' }
        $curlArgs += $Url

        # -S keeps -s quiet but still prints the error text; capture it instead of discarding it
        $out = & curl.exe @curlArgs 2>&1
        $exitCode = $LASTEXITCODE
        $stdout = ($out | Where-Object { $_ -is [string] -and $_ -match '^\d{3}\|[\d\.]+\|' } | Select-Object -Last 1)
        $curlError = (($out | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } |
                        ForEach-Object { $_.ToString().Trim() }) -join ' ')
        $rawHeaders = if (Test-Path $headerFile) { Get-Content $headerFile -Raw } else { '' }

        $statusCode   = $null
        $httpVersion  = $null
        $effectiveUrl = $Url
        if ($stdout -match '^(?<code>\d{3})\|(?<ver>[\d\.]+)\|(?<url>.*)$') {
            $statusCode   = $Matches['code']
            $httpVersion  = $Matches['ver']
            $effectiveUrl = $Matches['url']
        }

        return [pscustomobject]@{
            ExitCode    = $exitCode
            StatusCode  = $statusCode
            HttpVersion = $httpVersion
            EffectiveUrl = $effectiveUrl
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

    if ($curlHasHttp2) {
        $result.Http2Supported = ($scan.HttpVersion -eq '2')
    }
    else {
        $result.Http2Supported = 'Unknown'
        $h2Detail = $null
        if (($alpnAvailable -or $schannelAvailable) -and $scan.EffectiveUrl -match '^https://(?<h>[^/:]+)(?::(?<p>\d+))?') {
            $port = if ($Matches['p']) { [int]$Matches['p'] } else { 443 }
            $alpn = if ($alpnAvailable) { Test-H2Alpn -HostName $Matches['h'] -Port $port -TimeoutSeconds $TimeoutSeconds }
                    else                { Test-H2Schannel -HostName $Matches['h'] -Port $port -TimeoutSeconds $TimeoutSeconds }
            if ($null -ne $alpn) { $result.Http2Supported = $alpn } else { $h2Detail = $script:H2Detail }
        }
    }

    $result.VulnerableCandidate  = ($result.NginxDetected -and ($result.Http2Supported -eq $true))
    $result.DirectOriginExposure = ($result.VulnerableCandidate -and -not $result.FrontedByCdnWaf)

    if ($result.NginxDetected -and $result.Http2Supported -eq 'Unknown') {
        $result.Caveat = (@($result.Caveat, "nginx detected but HTTP/2 could not be tested - check manually. $h2Detail".Trim()) | Where-Object { $_ }) -join ' '
    }
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

$nginxOnly      = $results | Where-Object { $_.NginxDetected -and $_.Http2Supported -eq $false }
$nginxPlusHttp2 = $results | Where-Object { $_.NginxDetected -and $_.Http2Supported -eq $true }
$nginxUnknown   = $results | Where-Object { $_.NginxDetected -and $_.Http2Supported -eq 'Unknown' }

Write-Host "`n=== Summary ===" -ForegroundColor Yellow
Write-Host "Total URLs scanned   : $($results.Count)"
Write-Host "Fronted by CDN/WAF   : $(($results | Where-Object { $_.FrontedByCdnWaf }).Count)"
Write-Host "Errors / unreachable : $(($results | Where-Object { $_.Error }).Count)"
Write-Host "TLS not verified     : $(($results | Where-Object { -not $_.TlsVerified }).Count) (scanned anyway; see Caveat/Error columns)"

if ($nginxOnly.Count -gt 0) {
    Write-Host "`n[NOTICE] nginx detected on $($nginxOnly.Count) host(s):" -ForegroundColor Yellow
    $nginxOnly | Format-Table Region, Url, ServerHeader, NginxVersion, FrontedByCdnWaf -AutoSize
}

if ($nginxUnknown.Count -gt 0) {
    Write-Host "`n[NOTICE] nginx detected on $($nginxUnknown.Count) host(s) but HTTP/2 could NOT be tested (see warning at start):" -ForegroundColor Yellow
    $nginxUnknown | Format-Table Region, Url, ServerHeader, NginxVersion, FrontedByCdnWaf -AutoSize

    # Hand-off list: run the bash scanner on a machine whose curl has HTTP/2 (Linux, WSL, macOS):
    #   ./scan-nginx-exposure.sh -o h2.csv nginx=<this file>
    $listPath = [System.IO.Path]::ChangeExtension($OutputCsv, $null).TrimEnd('.') + '_nginx_hosts_to_test_h2.txt'
    $nginxUnknown | Select-Object -ExpandProperty Url -Unique | Set-Content -Path $listPath -Encoding ASCII
    Write-Host "List of these $($nginxUnknown.Count) nginx URLs for an HTTP/2 test elsewhere: $listPath" -ForegroundColor Yellow
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
