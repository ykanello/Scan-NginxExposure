#!/usr/bin/env bash
# Scan a list of URLs for nginx + HTTP/2 exposure (fingerprint only), using curl.
# Linux/macOS counterpart of Scan-NginxExposure.ps1 (same CSV columns).
#
# Usage: ./scan-nginx-exposure.sh [-o out.csv] [-t timeout] [-j jobs] [-k] [-s] REGION=file.txt ...
#   -k  skip certificate validation from the start
#   -s  strict TLS: no fallback to an unverified connection
# File format: one URL or host per line, '#' comments allowed.
set -u

out="nginx_scan_results_$(date +%Y%m%d_%H%M%S).csv"; timeout=10; jobs=8; skip=0; strict=0
while getopts "o:t:j:ks" o; do
  case $o in o) out=$OPTARG;; t) timeout=$OPTARG;; j) jobs=$OPTARG;; k) skip=1;; s) strict=1;; *) exit 2;; esac
done
shift $((OPTIND-1))
[ $# -ge 1 ] || { sed -n 2,9p "$0"; exit 2; }
command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TLS_CODES=" 35 51 53 54 58 59 60 64 66 77 80 82 83 90 91 "

csv() { local s=${1//\"/\"\"}; printf '"%s"' "$s"; }

scan_one() {  # region url
  local region=$1 url=$2 hdr res code ver rc err tlsok=True caveat="" first=""
  hdr=$(mktemp)
  run() {  # extra curl args...
    err=$(curl -sS -L --max-redirs 5 -o /dev/null -D "$hdr" --http2 -A "$UA" --max-time "$timeout" \
          -w '%{http_code}|%{http_version}' "$@" "$url" 2>&1 >"$hdr.out"); rc=$?
    res=$(cat "$hdr.out")
    err=$(printf '%s' "$err" | tr '\n\r' '  ' | sed 's/^curl: //;s/  */ /g;s/ More details here:.*//')
  }
  if [ "$skip" = 1 ]; then run -k; tlsok=False; else run; fi
  if [ "$strict" = 0 ] && [ "$skip" = 0 ] && [[ "$TLS_CODES" == *" $rc "* ]]; then
    first=$err; run -k; tlsok=False
    [ $rc -eq 0 ] && caveat="TLS certificate not verified (curl: $first). Server/HTTP2 data may come from a TLS-inspection proxy, not the origin."
  fi
  code=${res%%|*}; ver=${res##*|}
  if [ $rc -ne 0 ] || ! [[ "$res" =~ ^[0-9]{3}\|[0-9.]+$ ]]; then
    printf '%s,%s,,,False,,False,,False,False,False,,%s,%s\n' "$(csv "$region")" "$(csv "$url")" "$tlsok" "$(csv "curl exit code $rc: $err")"
    rm -f "$hdr" "$hdr.out"; return
  fi
  # last response block only (redirect hops repeat headers)
  local last server cdn="" nginx=False nver="" cdnflag=False h2=False vuln=False direct=False
  last=$(tr -d '\r' < "$hdr" | awk 'BEGIN{RS="";ORS="\n\n"} {b=$0} END{print b}')
  server=$(printf '%s\n' "$last" | grep -i '^server:' | tail -1 | sed 's/^[Ss][Ee][Rr][Vv][Ee][Rr]:[[:space:]]*//')
  printf '%s\n' "$last" | grep -qi '^cf-ray:'               && cdn+="Cloudflare,"
  [[ "${server,,}" == *cloudflare* ]]                      && cdn+="Cloudflare,"
  printf '%s\n' "$last" | grep -qi '^x-akamai-transformed:' && cdn+="Akamai,"
  printf '%s\n' "$last" | grep -qi '^x-amz-cf-id:'          && cdn+="CloudFront,"
  printf '%s\n' "$last" | grep -qi '^x-azure-ref:'          && cdn+="Azure Front Door,"
  if [ -n "$cdn" ]; then cdnflag=True; cdn=$(printf '%s' "${cdn%,}" | tr ',' '\n' | awk '!s[$0]++' | paste -sd, - | sed 's/,/, /g'); fi
  if [[ "${server,,}" =~ nginx(/([0-9.]+))? ]]; then nginx=True; nver=${BASH_REMATCH[2]:-}; fi
  [ "$ver" = 2 ] && h2=True
  [ $nginx = True ] && [ $h2 = True ] && vuln=True
  [ $vuln = True ] && [ $cdnflag = False ] && direct=True
  if [ $vuln = True ]; then
    if [ $cdnflag = True ]; then c="Behind $cdn - h2 negotiated at edge, origin not confirmed. WAF mitigates, does not fix - patch origin anyway."
    else c="No CDN/WAF detected - direct-to-origin exposure, high priority."; fi
    caveat="$c${caveat:+ $caveat}"
  fi
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,\n' "$(csv "$region")" "$(csv "$url")" "$code" "$(csv "$server")" \
    $nginx "$(csv "$nver")" $cdnflag "$(csv "$cdn")" $h2 $vuln $direct "$(csv "$caveat")" $tlsok
  rm -f "$hdr" "$hdr.out"
}
export -f scan_one csv; export UA timeout skip strict TLS_CODES

tmp=$(mktemp); n=0
for spec in "$@"; do
  region=${spec%%=*}; file=${spec#*=}
  [ -f "$file" ] || { echo "File not found: $file - skipping" >&2; continue; }
  while IFS= read -r line; do
    line=$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -z "$line" ] || [[ "$line" == \#* ]] && continue
    [[ "$line" =~ ^https?:// ]] || line="https://$line"
    printf '%s\0%s\0' "$region" "$line" >> "$tmp"; n=$((n+1))
  done < "$file"
done
[ $n -gt 0 ] || { echo "No URLs loaded." >&2; exit 1; }
echo "Loaded $n URLs. Scanning with curl ($jobs parallel)..." >&2

echo 'Region,Url,StatusCode,ServerHeader,NginxDetected,NginxVersion,FrontedByCdnWaf,CdnWafGuess,Http2Supported,VulnerableCandidate,DirectOriginExposure,Caveat,TlsVerified,Error' > "$out"
xargs -0 -n2 -P "$jobs" bash -c 'scan_one "$1" "$2"' _ < "$tmp" | sort -t, -k1,2 >> "$out"
rm -f "$tmp"

python3 - "$out" <<'EOF' 2>/dev/null || true
import csv,sys
r=list(csv.DictReader(open(sys.argv[1],newline='')))
b=lambda k:[x for x in r if x[k]=='True']
print(f"\n=== Summary ===\nTotal URLs scanned   : {len(r)}\nFronted by CDN/WAF   : {len(b('FrontedByCdnWaf'))}\nErrors / unreachable : {len([x for x in r if x['Error']])}\nTLS not verified     : {len([x for x in r if x['TlsVerified']=='False'])}")
print(f"nginx detected       : {len(b('NginxDetected'))}\nnginx + HTTP/2       : {len(b('VulnerableCandidate'))}\nDirect-origin (no CDN): {len(b('DirectOriginExposure'))}")
for x in b('VulnerableCandidate'): print(f"  [h2+nginx] {x['Region']:8} {x['Url']}  {x['ServerHeader']}  cdn={x['CdnWafGuess'] or '-'}")
print(f"\nResults written to: {sys.argv[1]}")
EOF
