#!/bin/sh
# export-bundle.sh - read-only evidence export for k8s-baseline-audit.
#
# Run by the cluster operator on their own admin host. Needs kubectl, jq (1.6 or
# newer) and sha256sum or shasum. Writes the same bundle as
# `k8s-baseline-audit collect` (manifest producer "export-script") and prints its path.
#
# usage: export-bundle.sh -o OUT_DIR [-c CONTEXT] [-k kubescape.json] [-t trivy.json]
#                         [-b NODE=kube-bench.json]...
# exit:  0 ok, 2 error
#
# Safety:
# - Every kubectl call passes kc_check first. It refuses anything except get, version,
#   api-resources, auth can-i, config current-context and config view.
# - Secret values are never requested: secrets are listed with a go-template that
#   prints names and data keys only.
# - Raw kubectl output is streamed into jq and never written to disk. Only redacted
#   output is written, first to a private temp dir, then moved into OUT_DIR.
# - Redaction and sanitizing mirror src/k8s_baseline_audit/collect/redact.py and
#   sanitize.py rule for rule, including which input shapes are rejected.
#   tests/test_export_script.py compares this script with the Python collector.
set -eu
umask 077

VERSION="0.1.0"
# shellcheck disable=SC2016 # Go template, not shell expansion
SECRET_TEMPLATE='{{range .items}}{{.metadata.namespace}}{{"\t"}}{{.metadata.name}}{{"\t"}}{{.type}}{{"\t"}}{{range $k, $v := .data}}{{$k}},{{end}}{{"\n"}}{{end}}'

# --- jq library -------------------------------------------------------------------------
# Python truthiness and "for x in (value or [])" semantics are reproduced exactly:
# where Python would raise, jq raises too (each_at / obj), and the caller fails closed.
# shellcheck disable=SC2016 # jq program, not shell expansion
JQ_LIB='
def truthy: . != null and . != false and . != 0 and . != "" and . != [] and . != {};
def shape: error("unexpected shape");
def obj: if type == "object" then . else shape end;
def each_at(k; f):
  if (.[k] | truthy) then .[k] |= (if type == "array" then map(f) else shape end) else . end;
def at(k; f): if has(k) then .[k] |= f else . end;
def strip: sub("\\A[\\s\u001c-\u001f]+"; "") | sub("[\\s\u001c-\u001f]+\\z"; "");
# [fromjson?] closes the try before the caller continues: jq 1.6 try would otherwise
# also catch later shape errors.
def parse: [fromjson?] | if length == 1 then .[0] else ("invalid JSON" | halt_error(2)) end;

# redact.py: redact_argv rules A-D. [-\p{L}\p{N}_.] equals Python [-\w.] on str.
# Every i is [iıİ]: Python re.IGNORECASE folds Turkish dotted/dotless i, Oniguruma does not.
def word: "(?:password|passwd|pass|pwd|token|secret|ap[iıİ][-_]?key|ap[iıİ]key|credent[iıİ]als?|dsn|bearer|pr[iıİ]vate[-_]?key)";
def keyre: "[-\\p{L}\\p{N}_.]*?" + word + "[-\\p{L}\\p{N}_.]*";
def sp: "\\s\u001c-\u001f";
def rule_a: "\\A(?<key>" + keyre + ")=(?<val>[^\\n]*)\\n?\\z";
def rule_b: "\\A-{1,2}" + keyre + "\\n?\\z";
def rule_c: "(?<pre>[a-zıİ][a-z0-9+.ıİ-]*://[^/:@" + sp + "]+:)[^@" + sp + "]+@";
def rule_d: "(?<key>" + keyre + ")=(?<val>\"[^\"]*\"|\u0027[^\u0027]*\u0027|[^" + sp + "\"\u0027]+)";
# Safe: true/false, or one path token (Python re.fullmatch(r"/\S*")).
def safe: (ascii_downcase | . == "true" or . == "false") or test("\\A/[^" + sp + "]*\\z");
def unquote:
  if (startswith("\"") and endswith("\"")) or (startswith("\u0027") and endswith("\u0027"))
  then .[1:-1] else . end;
# redact.py: redact_text (rules C and D on free text).
def redact_text:
  gsub(rule_c; "\(.pre)<redacted>@"; "i")
  | gsub(rule_d; (.val | unquote) as $u
      | if $u != "" and ($u | safe | not) then "\(.key)=<redacted>"
        else "\(.key)=\(.val)" end; "i");
def redact_list:
  . as $a
  | reduce range(0; length) as $i ({out: [], skip: false};
      if .skip then .skip = false
      else $a[$i] as $e
        | if ($e | type) != "string" then .out += [$e]
          elif ($e | test(rule_a; "i")) then
            ($e | capture(rule_a; "i")) as $m
            | .out += [if $m.val != "" and ($m.val | safe | not) then "\($m.key)=<redacted>" else $e end]
          elif ($e | test(rule_b; "i"))
               and ($a[$i + 1] | type == "string" and . != "" and ((startswith("-") or safe) | not))
          then .out += [$e, "<redacted>"] | .skip = true
          else .out += [$e | redact_text]
          end
      end)
  | .out;
def argv:
  if type == "array" then redact_list
  elif type == "string" then [explode[] | [.] | implode]
  elif type == "object" and length == 0 then []
  else shape end;

# redact.py: redact_pod_list.
def headers:
  if truthy then
    if type == "array" then
      map(if type == "object" and (.value | truthy) then .value = "<redacted>" else . end)
    elif type == "object" or type == "string" then .
    else shape end
  else . end;
def handler:
  if type == "object" then
    (if (.exec | type) == "object" and (.exec | has("command")) then .exec.command |= argv else . end)
    | (if (.httpGet | type) == "object" and (.httpGet | has("httpHeaders"))
       then .httpGet.httpHeaders |= headers else . end)
  else . end;
def container:
  obj
  | each_at("env"; obj | if (.value | truthy) then .value = "<redacted>" else . end)
  | (if (.command | truthy) then .command |= argv else . end)
  | (if (.args | truthy) then .args |= argv else . end)
  | reduce ("livenessProbe", "readinessProbe", "startupProbe") as $p (.; at($p; handler))
  | if (.lifecycle | truthy) and (.lifecycle | type) == "object"
    then .lifecycle |= reduce ("postStart", "preStop") as $h (.; at($h; handler))
    else . end;
def mask(k; o):
  if (.[k] | truthy) and (.[k] | obj | .[o] | type) == "object"
  then .[k][o] |= with_entries(.value = "<redacted>") else . end;
def volume: obj | mask("flexVolume"; "options") | mask("csi"; "volumeAttributes");
def pod:
  obj
  | del(.status)
  | (if (.metadata | truthy) then .metadata |= (obj | del(.annotations)) else . end)
  | if (.spec | truthy) then .spec |= (obj
        | each_at("volumes"; volume)
        | each_at("initContainers"; container)
        | each_at("containers"; container)
        | each_at("ephemeralContainers"; container))
    else . end;
def redact_pods:
  if type == "object" and (.items | type) == "array" then .items |= map(pod) else shape end;

# redact.py: parse_secret_rows. The split mirrors Python str.splitlines().
def secret_rows:
  [splits("\r\n|[\n\r\u000b\u000c\u001c-\u001e\u0085\u2028\u2029]")]
  | map(select(strip != "")
      | (split("\t") + ["", "", "", ""]) as $f
      | {metadata: {namespace: $f[0], name: $f[1]}, type: $f[2],
         keys: ($f[3] | split(",") | map(select(. != "")) | sort)})
  | {items: .};

# sanitize.py. Top-level shapes the parsers need are required (fail closed), and
# free-form records are reduced to allowlisted fields.
def pick(keys): obj | with_entries(select(.key as $k | any(keys; . == $k)));
def identity:
  . as $o
  | reduce ("apiVersion", "apiGroup", "kind", "name", "namespace") as $k
      ({}; if $o[$k] != null then .[$k] = $o[$k] else . end)
  | if ($o.metadata | type) == "object" then
      .metadata = ($o.metadata as $md | reduce ("name", "namespace") as $k
        ({}; if $md[$k] != null then .[$k] = $md[$k] else . end))
    else . end;
def ks_control:
  pick("controlID", "name", "severity", "status")
  | if (.status | type) == "object" then .status |= pick("status") else . end;
def ks_result:
  pick("resourceID", "controls")
  | if has("controls") then .controls |= (if type == "array" then map(ks_control) else shape end) else . end;
def ks_resource:
  pick("resourceID", "object") | if (.object | type) == "object" then .object |= identity else . end;
def sanitize_kubescape:
  if type == "object" and (.results | type) == "array"
     and ((has("resources") | not) or (.resources | type) == "array")
  then
    . as $d
    | {results: ($d.results | map(ks_result))}
    + (if ($d | has("resources")) then {resources: ($d.resources | map(ks_resource))} else {} end)
    + (if ($d.summaryDetails | type) == "object" and ($d.summaryDetails.controls | type) == "object"
       then {summaryDetails: {controls: ($d.summaryDetails.controls
              | with_entries(select(.value | type == "object")
                  | .value |= pick("name", "severity", "controlID")))}}
       else {} end)
  else shape end;
def image:
  if type == "array" then map(image)
  elif type == "object" then
    with_entries(select(.key == "RepoTags" or .key == "RepoDigests" or .key == "ImageID" or .key == "OS"))
  else . end;
def secret:
  . as $s
  | pick("RuleID", "Category", "Severity", "Title", "StartLine", "EndLine")
  | if ($s.Layer | type) == "object" then .Layer = ($s.Layer | pick("Digest", "DiffID")) else . end;
def trivy_result:
  pick("Target", "Class", "Type", "Metadata", "Misconfigurations", "Vulnerabilities", "Secrets")
  | at("Metadata"; image)
  | each_at("Misconfigurations"; pick("ID", "AVDID", "Title", "Severity", "Status", "Resolution"))
  | each_at("Vulnerabilities"; pick("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity"))
  | each_at("Secrets"; secret);
def trivy_resource:
  pick("Namespace", "Kind", "Name", "Metadata", "Results") | at("Metadata"; image) | each_at("Results"; trivy_result);
def sanitize_trivy:
  if type == "object" and (.Resources | type) == "array" then
    . as $d
    | {Resources: ($d.Resources | map(trivy_resource))}
    + (if ($d | has("ClusterName")) then {ClusterName: $d.ClusterName} else {} end)
  else shape end;
def bench_test:
  pick("section", "desc", "results")
  | each_at("results"; pick("test_number", "test_desc", "status", "scored", "remediation", "type"));
def bench_control:
  pick("id", "version", "text", "node_type", "tests") | each_at("tests"; bench_test);
def sanitize_kube_bench:
  if type == "object" and (.Controls | type) == "array" then {Controls: (.Controls | map(bench_control))}
  else shape end;
'

# --- helpers ----------------------------------------------------------------------------

USAGE="usage: $0 -o OUT_DIR [-c CONTEXT] [-k kubescape.json] [-t trivy.json] [-b NODE=kube-bench.json]..."
usage() {
  printf '%s\n' "$USAGE" >&2
  exit 2
}
die() {
  printf 'export-bundle: %s\n' "$*" >&2
  exit 2
}

TMP=""
cleanup() {
  status=$?
  if [ -n "$TMP" ]; then rm -r "$TMP"; fi
  if [ "$status" -ne 0 ]; then exit 2; fi
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

for tool in kubectl jq; do
  command -v "$tool" > /dev/null 2>&1 || die "$tool not found on PATH"
done
if command -v sha256sum > /dev/null 2>&1; then
  SHA="sha256sum"
elif command -v shasum > /dev/null 2>&1; then
  SHA="shasum"
else
  die "sha256sum or shasum not found on PATH"
fi

sha() {
  if [ "$SHA" = sha256sum ]; then sha256sum < "$1"; else shasum -a 256 < "$1"; fi | cut -d' ' -f1
}

# Mirrors collector._slug / scanners._slug.
slug() {
  jq -n -r --arg s "$1" --arg d "$2" \
    '$s | gsub("[^A-Za-z0-9._-]+"; "-") | sub("\\A-+"; "") | sub("-+\\z"; "") | if . == "" then $d else . end'
}

set_status() {
  jq -c --arg n "$1" --argjson s "$2" '.[$n] = $s' "$TMP/scanners.json" > "$TMP/scanners.new"
  mv "$TMP/scanners.new" "$TMP/scanners.json"
}

# import_scanner NAME FILE JQ_FUNCTION
import_scanner() {
  [ -f "$2" ] || die "scanner result file not found: $2"
  [ ! -e "$STAGE/scanners/$1.json" ] || die "duplicate scanner result: $1"
  mkdir -p "$STAGE/scanners"
  jq -R -s -S "$JQ_LIB parse | $3" < "$2" > "$STAGE/scanners/$1.json" 2> /dev/null \
    || die "$2 is not a valid $1 result"
}

kc_check() {
  case "${1:-}" in
    get | version | api-resources) ;;
    auth) [ "${2:-}" = can-i ] || die "refusing kubectl $1 ${2:-}" ;;
    config)
      case "${2:-}" in
        current-context | view) ;;
        *) die "refusing kubectl $1 ${2:-}" ;;
      esac
      ;;
    *) die "refusing kubectl ${1:-}" ;;
  esac
}

log_command() {
  code=$1
  shift
  argv='["kubectl"'
  for arg in "$@"; do
    case $arg in
      *[\"\\]* | *[![:print:]]*) argv="$argv,$(printf '%s' "$arg" | jq -R -s .)" ;;
      *) argv="$argv,\"$arg\"" ;; # printable ASCII without quote or backslash is valid JSON
    esac
  done
  printf '{"argv":%s],"exit_code":%s}\n' "$argv" "$code" >> "$TMP/commands.jsonl"
}

# Runs kubectl. stdout passes through, stderr goes to $TMP/stderr, the exit code to $TMP/rc.
# Only call after kc_check.
kc_exec() {
  if [ -n "$CTX" ]; then set -- --context "$CTX" "$@"; fi
  rc=0
  kubectl "$@" 2> "$TMP/stderr" || rc=$?
  printf '%s\n' "$rc" > "$TMP/rc"
  log_command "$rc" "$@"
}

# fetch JQ_PROGRAM KUBECTL_ARGS...: kubectl stdout is piped straight into jq.
# Sets KRC (kubectl exit code) and JRC (jq exit code: 0 ok, 2 invalid JSON, other shape).
fetch() {
  prog=$1
  shift
  kc_check "$@"
  JRC=0
  rm -f "$TMP/rc" # a stale exit code must never be reused
  kc_exec "$@" | jq -R -s -S "$JQ_LIB $prog" > "$TMP/out" 2> /dev/null || JRC=$?
  KRC=$(cat "$TMP/rc")
}

# capture KUBECTL_ARGS...: stdout, stripped like Python str.strip(), in $TEXT.
capture() {
  fetch "strip" "$@"
  [ "$JRC" = 0 ] || die "could not read kubectl output"
  TEXT=$(jq -r . "$TMP/out")
}

# Mirrors collector._reason: stderr only, never stdout, redacted (rules C and D).
reason() {
  jq -R -s -r --arg rc "$KRC" "$JQ_LIB"'
    strip | redact_text | .[-500:] | if . == "" then "kubectl exit \($rc)" else "kubectl exit \($rc): \(.)" end' \
    < "$TMP/stderr"
}

err() {
  jq -c -n --arg r "$1" --arg m "$2" '{resource: $r, reason: $m}' >> "$TMP/errors.jsonl"
}

# --- arguments --------------------------------------------------------------------------

TMP=$(mktemp -d)
STAGE="$TMP/bundle"
mkdir "$STAGE" "$STAGE/resources"
: > "$TMP/commands.jsonl"
: > "$TMP/errors.jsonl"
: > "$TMP/kb.nodes"
printf '{}' > "$TMP/scanners.json"

OUT="" CTX=""
while getopts "o:c:k:t:b:h" opt; do
  case "$opt" in
    o) OUT=$OPTARG ;;
    c) CTX=$OPTARG ;;
    k)
      import_scanner kubescape "$OPTARG" sanitize_kubescape
      set_status kubescape '{"status":"imported"}'
      ;;
    t)
      import_scanner trivy "$OPTARG" sanitize_trivy
      set_status trivy '{"status":"imported"}'
      ;;
    b)
      node=${OPTARG%%=*}
      file=${OPTARG#*=}
      { [ "$node" != "$OPTARG" ] && [ -n "$node" ] && [ -n "$file" ]; } \
        || die "-b expects NODE=FILE, got: $OPTARG"
      import_scanner "kube-bench-$(slug "$node" node)" "$file" sanitize_kube_bench
      slug "$node" node >> "$TMP/kb.nodes"
      ;;
    h)
      printf '%s\n' "$USAGE"
      exit 0
      ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || usage
[ -n "$OUT" ] || usage
if [ -s "$TMP/kb.nodes" ]; then
  set_status kube-bench "$(jq -R -s -c '{status: "imported", nodes: (split("\n") | map(select(. != "")))}' "$TMP/kb.nodes")"
fi

# --- collection (mirrors collector.collect) -----------------------------------------------

capture config current-context
if [ "$KRC" = 0 ] && [ -n "$TEXT" ]; then
  CONTEXT=$TEXT
else
  CONTEXT=${CTX:-unknown}
fi
capture config view --minify -o 'jsonpath={.clusters[0].cluster.server}'
if [ "$KRC" = 0 ]; then SERVER=$TEXT; else SERVER=""; fi

fetch "parse" version -o json
if [ "$JRC" = 0 ]; then
  mv "$TMP/out" "$STAGE/resources/version.json"
else
  err version "$(reason)"
fi

PREFLIGHT=""
for kind in namespaces nodes pods serviceaccounts roles clusterroles rolebindings \
  clusterrolebindings networkpolicies secrets; do
  case $kind in
    pods | serviceaccounts | roles | rolebindings | networkpolicies | secrets) set -- --all-namespaces ;;
    *) set -- ;;
  esac
  capture auth can-i list "$kind" "$@"
  answer=$TEXT
  if [ "$KRC" = 0 ] && [ "$answer" = yes ]; then
    PREFLIGHT="$PREFLIGHT\"$kind\":true,"
  else
    PREFLIGHT="$PREFLIGHT\"$kind\":false,"
    if [ "$KRC" = 1 ] && [ "$answer" = no ]; then
      err "$kind" "forbidden: kubectl auth can-i list returned no"
    else
      err "$kind" "preflight failed: $(reason)"
    fi
    continue
  fi
  if [ "$kind" = secrets ]; then
    fetch "secret_rows" get secrets "$@" -o "go-template=$SECRET_TEMPLATE"
    if [ "$KRC" != 0 ]; then
      err secrets "$(reason)"
      continue
    fi
    [ "$JRC" = 0 ] || die "could not parse the secret listing"
    mv "$TMP/out" "$STAGE/resources/secrets.json"
    continue
  fi
  if [ "$kind" = pods ]; then prog="parse | redact_pods"; else prog="parse"; fi
  fetch "$prog" get "$kind" "$@" -o json
  if [ "$KRC" != 0 ]; then
    err "$kind" "$(reason)"
    continue
  fi
  case $JRC in
    0) mv "$TMP/out" "$STAGE/resources/$kind.json" ;;
    2) err "$kind" "kubectl returned invalid JSON" ;;
    *) err "$kind" "unexpected kubectl output shape" ;;
  esac
done

printf '{%s}' "${PREFLIGHT%,}" | jq -S . > "$STAGE/preflight.json"
jq -s -S '{errors: .}' "$TMP/errors.jsonl" > "$STAGE/errors.json"

# --- manifest ---------------------------------------------------------------------------

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
STAMP=$(printf '%s' "$NOW" | tr -d ':-')
NAME="bundle-$(slug "$CONTEXT" cluster)-$STAMP"

(cd "$STAGE" && find . -type f) | sed 's|^\./||' | LC_ALL=C sort > "$TMP/files"
: > "$TMP/hashes.tsv"
while IFS= read -r f; do
  printf '%s\t%s\n' "$f" "$(sha "$STAGE/$f")" >> "$TMP/hashes.tsv"
done < "$TMP/files"

jq -n -S \
  --arg created "$NOW" --arg ctx "$CONTEXT" --arg server "$SERVER" --arg version "$VERSION" \
  --slurpfile commands "$TMP/commands.jsonl" --slurpfile scanners "$TMP/scanners.json" \
  --rawfile hashes "$TMP/hashes.tsv" \
  '{schema: "k8s-baseline-audit/bundle/v1", producer: "export-script", created_at: $created,
    cluster: {context: $ctx, server: $server},
    tool: {name: "k8s-baseline-audit-export", version: $version},
    commands: $commands, scanners: $scanners[0],
    files: ($hashes | split("\n") | map(select(. != "") | split("\t") | {(.[0]): .[1]}) | add // {})}' \
  > "$STAGE/manifest.json"

mkdir -p -- "$OUT" || die "cannot create $OUT"
mkdir -- "$OUT/$NAME" 2> /dev/null || die "$OUT/$NAME already exists or cannot be created"
mv "$STAGE"/* "$OUT/$NAME"/
printf '%s\n' "$OUT/$NAME"
