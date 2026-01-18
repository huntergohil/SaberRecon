from datetime import datetime
from urllib.parse import urlparse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
import subprocess
import random
import string
import base64
import mimetypes

TOOL_DEFS = {
    "whois": {
        "title": "WHOIS Lookup",
        "kind": "domain",
        "base": ["whois"],
        "groups": [
            {
                "name": "Common flags",
                "options": [
                    {"flag": "-a", "type": "bool", "label": "Search all WHOIS servers (-a)", "default": False},
                    {"flag": "-A", "type": "bool", "label": "Search all WHOIS servers (alternate) (-A)", "default": False},
                    {"flag": "-b", "type": "bool", "label": "Verbose (depends on implementation) (-b)", "default": False},
                    {"flag": "-f", "type": "bool", "label": "Fast output / no recursive lookups (-f)", "default": False},
                    {"flag": "-g", "type": "bool", "label": "Use gTLD WHOIS server (-g)", "default": False},
                    {"flag": "-i", "type": "bool", "label": "Use IANA lookups (-i)", "default": False},
                    {"flag": "-I", "type": "bool", "label": "Disable IDN handling (-I)", "default": False},
                    {"flag": "-k", "type": "bool", "label": "Keep connection open if supported (-k)", "default": False},
                    {"flag": "-l", "type": "bool", "label": "Disable referral lookups (-l)", "default": False},
                    {"flag": "-m", "type": "bool", "label": "Disable recursive lookups (-m)", "default": False},
                    {"flag": "-P", "type": "bool", "label": "Disable partial output trimming (-P)", "default": False},
                    {"flag": "-Q", "type": "bool", "label": "Quick mode (-Q)", "default": False},
                    {"flag": "-r", "type": "bool", "label": "Disable following referrals (-r)", "default": False},
                    {"flag": "-R", "type": "bool", "label": "Recursively query related servers (-R)", "default": False},
                    {"flag": "-S", "type": "bool", "label": "Disable caching (if supported) (-S)", "default": False},
                ],
            },
            {
                "name": "Server / Region",
                "options": [
                    {
                        "flag": "__server_mode__",
                        "type": "choice",
                        "label": "Server selection (choose ONE)",
                        "choices": [
                            {"label": "Default behavior", "value": ""},
                            {"label": "Use country code server (-c <cc>)", "value": "country"},
                            {"label": "Use specific WHOIS host (-h <hostname>)", "value": "host"},
                        ],
                        "default": "",
                    },
                    {"flag": "-c", "type": "str", "label": "Country code (e.g., us, uk, de)", "default": ""},
                    {"flag": "-h", "type": "str", "label": "WHOIS server hostname", "default": ""},
                    {"flag": "-p", "type": "int", "label": "WHOIS port (-p <port>)", "default": 0, "min": 1, "max": 65535},
                ],
            },
        ],
    },
    "nslookup": {
        "title": "NSLookup",
        "kind": "domain",
        "base": ["nslookup"],
        "groups": [
            {
                "name": "Query basics",
                "options": [
                    {"flag": "-type", "type": "choice", "label": "Record type", "choices": ["A","AAAA","CNAME","MX","NS","SOA","TXT","SRV","PTR","CAA"], "default": "A"},
                    {"flag": "-class", "type": "choice", "label": "Query class", "choices": ["IN","CH","HS"], "default": "IN"},
                ],
            },
            {
                "name": "Resolver behavior",
                "options": [
                    {"flag": "-recurse", "type": "bool", "label": "Recursion on (-recurse)", "default": True},
                    {"flag": "-nosearch", "type": "bool", "label": "Disable search list (-nosearch)", "default": False},
                    {"flag": "-search", "type": "bool", "label": "Use search list (-search)", "default": False},
                    {"flag": "-vc", "type": "bool", "label": "Use TCP (-vc)", "default": False},
                ],
            },
            {
                "name": "Timeouts / retries",
                "options": [
                    {"flag": "-timeout", "type": "int", "label": "Timeout (seconds)", "default": 2, "min": 1, "max": 60},
                    {"flag": "-retry", "type": "int", "label": "Retries", "default": 1, "min": 0, "max": 10},
                    {"flag": "-port", "type": "int", "label": "DNS server port", "default": 53, "min": 1, "max": 65535},
                ],
            },
            {
                "name": "Output / debugging",
                "options": [
                    {"flag": "-debug", "type": "bool", "label": "Debug (-debug)", "default": False},
                    {"flag": "-d2", "type": "bool", "label": "Extra debug (-d2)", "default": False},
                    {"flag": "-sil", "type": "bool", "label": "Silent (less output) (-sil)", "default": False},
                ],
            },
            {
                "name": "Advanced",
                "options": [
                    {"flag": "-domain", "type": "str", "label": "Default domain (-domain <name>)", "default": ""},
                    {"flag": "-srchlist", "type": "str", "label": "Search list (-srchlist <a/b/c>)", "default": ""},
                ],
            },
            {
                "name": "Optional DNS server",
                "options": [
                    {"flag": "__server__", "type": "str", "label": "DNS Server (optional)", "default": ""},
                ],
            },
        ],
    },
    "dig": {
        "title": "DIG (DNS Lookup)",
        "kind": "domain",
        "base": ["dig"],
        "groups": [

            {
                "name": "Query basics",
                "options": [
                    {
                        "flag": "-t",
                        "type": "choice",
                        "label": "Record type",
                        "choices": [
                            "A", "AAAA", "ANY", "CNAME", "MX", "NS", "SOA",
                            "TXT", "SRV", "PTR", "CAA"
                        ],
                        "default": "A",
                    },
                    {
                        "flag": "-c",
                        "type": "choice",
                        "label": "Query class",
                        "choices": ["IN", "CH", "HS"],
                        "default": "IN",
                    },
                    {
                        "flag": "-x",
                        "type": "bool",
                        "label": "Reverse lookup (-x)",
                        "default": False,
                    },
                ],
            },
    
            {
                "name": "Transport & protocol",
                "options": [
                    {"flag": "-4", "type": "bool", "label": "IPv4 only (-4)", "default": False},
                    {"flag": "-6", "type": "bool", "label": "IPv6 only (-6)", "default": False},
                    {"flag": "+tcp", "type": "bool", "label": "Force TCP (+tcp)", "default": False},
                    {"flag": "+notcp", "type": "bool", "label": "Disable TCP (+notcp)", "default": False},
                ],
            },
    
            {
                "name": "Output formatting",
                "options": [
                    {"flag": "+short", "type": "bool", "label": "Short answer only (+short)", "default": False},
                    {"flag": "+noall", "type": "bool", "label": "Disable all sections (+noall)", "default": False},
                    {"flag": "+answer", "type": "bool", "label": "Show answer section (+answer)", "default": False},
                    {"flag": "+authority", "type": "bool", "label": "Show authority section (+authority)", "default": False},
                    {"flag": "+additional", "type": "bool", "label": "Show additional section (+additional)", "default": False},
                    {"flag": "+stats", "type": "bool", "label": "Show query stats (+stats)", "default": False},
                ],
            },

            {
                "name": "DNS behavior",
                "options": [
                    {"flag": "+recurse", "type": "bool", "label": "Recursive query (+recurse)", "default": True},
                    {"flag": "+norecurse", "type": "bool", "label": "Disable recursion (+norecurse)", "default": False},
                    {"flag": "+trace", "type": "bool", "label": "Trace delegation path (+trace)", "default": False},
                    {"flag": "+dnssec", "type": "bool", "label": "Request DNSSEC records (+dnssec)", "default": False},
                ],
            },

            {
                "name": "Timeouts & retries",
                "options": [
                    {
                        "flag": "+time",
                        "type": "int",
                        "label": "Query timeout (seconds)",
                        "default": 5,
                        "min": 1,
                        "max": 60,
                    },
                    {
                        "flag": "+tries",
                        "type": "int",
                        "label": "Retry attempts",
                        "default": 3,
                        "min": 1,
                        "max": 10,
                    },
                ],
            },
    
            {
                "name": "Advanced",
                "options": [
                    {
                        "flag": "@",
                        "type": "str",
                        "label": "DNS server (@server)",
                        "default": "",
                    },
                    {
                        "flag": "+bufsize",
                        "type": "int",
                        "label": "EDNS buffer size (+bufsize)",
                        "default": 1232,
                        "min": 512,
                        "max": 4096,
                    },
                ],
            },
        ],
    },
    "nmap": {
        "title": "Nmap",
        "kind": "domain",
        "base": ["nmap"],
        "groups": [
            {
                "name": "Target Specification",
                "options": [
                    {"flag": "-iL", "type": "str", "label": "Input list (-iL <file>)", "default": ""},
                    {"flag": "-iR", "type": "int", "label": "Random targets (-iR <num>)", "default": 0, "min": 0, "max": 1000000},
                    {"flag": "--exclude", "type": "str", "label": "Exclude (--exclude a,b,c)", "default": ""},
                    {"flag": "--excludefile", "type": "str", "label": "Exclude file (--excludefile <file>)", "default": ""},
                ],
            },
            {
                "name": "Host Discovery",
                "options": [
                    {"flag": "-sL", "type": "bool", "label": "List scan (-sL)", "default": False},
                    {"flag": "-sn", "type": "bool", "label": "Ping scan (-sn)", "default": False},
                    {"flag": "-Pn", "type": "bool", "label": "Treat hosts as online (-Pn)", "default": False},
                    {"flag": "--traceroute", "type": "bool", "label": "Traceroute (--traceroute)", "default": False},
                    {"flag": "-n", "type": "bool", "label": "Never resolve DNS (-n)", "default": False},
                    {"flag": "-R", "type": "bool", "label": "Always resolve DNS (-R)", "default": False},
                    {"flag": "--dns-servers", "type": "str", "label": "DNS servers (--dns-servers a,b,c)", "default": ""},
                    {"flag": "--system-dns", "type": "bool", "label": "Use system DNS (--system-dns)", "default": False},
                    {"flag": "-PS", "type": "str", "label": "TCP SYN discovery (-PS<ports>)", "default": ""},
                    {"flag": "-PA", "type": "str", "label": "TCP ACK discovery (-PA<ports>)", "default": ""},
                    {"flag": "-PU", "type": "str", "label": "UDP discovery (-PU<ports>)", "default": ""},
                    {"flag": "-PY", "type": "str", "label": "SCTP discovery (-PY<ports>)", "default": ""},
                    {"flag": "-PE", "type": "bool", "label": "ICMP echo (-PE)", "default": False},
                    {"flag": "-PP", "type": "bool", "label": "ICMP timestamp (-PP)", "default": False},
                    {"flag": "-PM", "type": "bool", "label": "ICMP netmask (-PM)", "default": False},
                    {"flag": "-PO", "type": "str", "label": "IP protocol ping (-PO<proto>)", "default": ""},
                ],
            },
            {
                "name": "Scan Technique",
                "options": [
                    {"flag": "__scan_type__", "type": "choice", "label": "Technique",
                     "choices": [
                         {"label": "Default", "value": ""},
                         {"label": "SYN (-sS)", "value": "-sS"},
                         {"label": "Connect (-sT)", "value": "-sT"},
                         {"label": "ACK (-sA)", "value": "-sA"},
                         {"label": "Window (-sW)", "value": "-sW"},
                         {"label": "Maimon (-sM)", "value": "-sM"},
                         {"label": "UDP (-sU)", "value": "-sU"},
                         {"label": "Null (-sN)", "value": "-sN"},
                         {"label": "FIN (-sF)", "value": "-sF"},
                         {"label": "Xmas (-sX)", "value": "-sX"},
                         {"label": "SCTP INIT (-sY)", "value": "-sY"},
                         {"label": "SCTP COOKIE (-sZ)", "value": "-sZ"},
                         {"label": "IP protocol (-sO)", "value": "-sO"},
                     ],
                     "default": ""
                    },
                    {"flag": "--scanflags", "type": "str", "label": "Custom scan flags (--scanflags <flags>)", "default": ""},
                    {"flag": "-sI", "type": "str", "label": "Idle scan (-sI <zombie[:port]>)", "default": ""},
                    {"flag": "-b", "type": "str", "label": "FTP bounce (-b <ftp relay>)", "default": ""},
                ],
            },
            {
                "name": "Ports",
                "options": [
                    {"flag": "-p", "type": "str", "label": "Ports (-p <ranges>)", "default": ""},
                    {"flag": "--exclude-ports", "type": "str", "label": "Exclude ports (--exclude-ports <ranges>)", "default": ""},
                    {"flag": "-F", "type": "bool", "label": "Fast mode (-F)", "default": False},
                    {"flag": "-r", "type": "bool", "label": "Sequential (-r)", "default": False},
                    {"flag": "--top-ports", "type": "int", "label": "Top ports (--top-ports <n>)", "default": 0, "min": 0, "max": 5000},
                    {"flag": "--port-ratio", "type": "str", "label": "Port ratio (--port-ratio <ratio>)", "default": ""},
                ],
            },
            {
                "name": "Detection (Version / Scripts / OS)",
                "options": [
                    {"flag": "-sV", "type": "bool", "label": "Version detection (-sV)", "default": False},
                    {"flag": "--version-intensity", "type": "int", "label": "Version intensity (0-9)", "default": 0, "min": 0, "max": 9},
                    {"flag": "-sC", "type": "bool", "label": "Default scripts (-sC)", "default": False},
                    {"flag": "--script", "type": "str", "label": "Scripts (--script <list>)", "default": ""},
                    {"flag": "--script-args", "type": "str", "label": "Script args (--script-args k=v,...)", "default": ""},
                    {"flag": "-O", "type": "bool", "label": "OS detection (-O)", "default": False},
                    {"flag": "--osscan-guess", "type": "bool", "label": "OS guess (--osscan-guess)", "default": False},
                ],
            },
            {
                "name": "Timing",
                "options": [
                    {"flag": "-T", "type": "int", "label": "Timing (-T0..5)", "default": 0, "min": 0, "max": 5},
                    {"flag": "--max-retries", "type": "int", "label": "Max retries (--max-retries <n>)", "default": 0, "min": 0, "max": 50},
                    {"flag": "--host-timeout", "type": "str", "label": "Host timeout (--host-timeout <time>)", "default": ""},
                    {"flag": "--min-rate", "type": "int", "label": "Min rate (--min-rate <n>)", "default": 0, "min": 0, "max": 1000000},
                    {"flag": "--max-rate", "type": "int", "label": "Max rate (--max-rate <n>)", "default": 0, "min": 0, "max": 1000000},
                ],
            },
            {
                "name": "Output & Verbosity",
                "options": [
                    {"flag": "-v", "type": "count", "label": "Verbosity (-v / -vv / ...)", "default": 0, "min": 0, "max": 5},
                    {"flag": "-d", "type": "count", "label": "Debug (-d / -dd / ...)", "default": 0, "min": 0, "max": 5},
                    {"flag": "--reason", "type": "bool", "label": "Show reasons (--reason)", "default": False},
                    {"flag": "--open", "type": "bool", "label": "Only open (--open)", "default": False},
                    {"flag": "--packet-trace", "type": "bool", "label": "Packet trace (--packet-trace)", "default": False},
                ],
            },
            {
                "name": "Misc",
                "options": [
                    {"flag": "-6", "type": "bool", "label": "IPv6 (-6)", "default": False},
                    {"flag": "-A", "type": "bool", "label": "Aggressive (-A)", "default": False},
                    {"flag": "--privileged", "type": "bool", "label": "Assume privileged (--privileged)", "default": False},
                    {"flag": "--unprivileged", "type": "bool", "label": "Assume unprivileged (--unprivileged)", "default": False},
                ],
            },
        ],
    },
    "curl": {
        "title": "curl (HTTP Request)",
        "kind": "url",
        "base": ["curl"],
        "groups": [
    
            {
                "name": "Request basics",
                "options": [
                    {"flag": "-I", "type": "bool", "label": "HEAD request (headers only) (-I)", "default": True},
                    {"flag": "-L", "type": "bool", "label": "Follow redirects (-L)", "default": True},
    
                    {
                        "flag": "-X",
                        "type": "choice",
                        "label": "HTTP method (-X)",
                        "choices": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
                        "default": "GET",
                    },
    
                    {"flag": "--compressed", "type": "bool", "label": "Request compressed response (--compressed)", "default": True},
                    {"flag": "-A", "type": "str", "label": "User-Agent (-A)", "default": ""},
                ],
            },
    
            {
                "name": "Headers",
                "options": [
                    {"flag": "-H", "type": "str", "label": "Add header (-H)  (example: 'Accept: */*')", "default": ""},
                    {"flag": "-e", "type": "str", "label": "Referer (-e)", "default": ""},
                    {"flag": "-b", "type": "str", "label": "Cookie (-b)  (example: 'key=value')", "default": ""},
                ],
            },
    
            {
                "name": "Body / data",
                "options": [
                    {"flag": "-d", "type": "str", "label": "Data (-d)  (implies POST unless -X set)", "default": ""},
                    {"flag": "--data-urlencode", "type": "str", "label": "URL-encode data (--data-urlencode)", "default": ""},
                    {"flag": "-F", "type": "str", "label": "Multipart form (-F)  (example: 'a=1')", "default": ""},
                    {"flag": "--json", "type": "str", "label": "JSON body (--json)  (example: '{\"a\":1}')", "default": ""},
                ],
            },
    
            {
                "name": "Auth",
                "options": [
                    {"flag": "-u", "type": "str", "label": "Basic auth (-u)  (user:pass)", "default": ""},
                    {"flag": "-H_AUTH", "type": "str", "label": "Bearer token (adds Authorization header)", "default": ""},
                    {"flag": "--anyauth", "type": "bool", "label": "Try any auth method (--anyauth)", "default": False},
                ],
            },
    
            {
                "name": "TLS / HTTPS",
                "options": [
                    {"flag": "-k", "type": "bool", "label": "Insecure (skip TLS verify) (-k)", "default": False},
                    {"flag": "--http1.1", "type": "bool", "label": "Force HTTP/1.1 (--http1.1)", "default": False},
                    {"flag": "--http2", "type": "bool", "label": "Force HTTP/2 (--http2)", "default": False},
                    {"flag": "--tlsv1.2", "type": "bool", "label": "Force TLS 1.2 (--tlsv1.2)", "default": False},
                    {"flag": "--tlsv1.3", "type": "bool", "label": "Force TLS 1.3 (--tlsv1.3)", "default": False},
                ],
            },
    
            {
                "name": "Output / verbosity",
                "options": [
                    {"flag": "-v", "type": "bool", "label": "Verbose (-v)", "default": False},
                    {"flag": "-i", "type": "bool", "label": "Include response headers (-i)", "default": False},
                    {"flag": "-s", "type": "bool", "label": "Silent (-s)", "default": False},
                    {"flag": "-S", "type": "bool", "label": "Show errors (-S)", "default": False},
                    {"flag": "-o", "type": "str", "label": "Write output to file (-o) (container path)", "default": ""},
                ],
            },
    
            {
                "name": "Timeouts / limits",
                "options": [
                    {"flag": "--connect-timeout", "type": "int", "label": "Connect timeout seconds", "default": 10, "min": 1, "max": 120},
                    {"flag": "-m", "type": "int", "label": "Max time seconds (-m)", "default": 30, "min": 1, "max": 600},
                    {"flag": "--max-redirs", "type": "int", "label": "Max redirects (--max-redirs)", "default": 10, "min": 0, "max": 50},
                ],
            },
        ],
    },
    "whatweb": {
        "title": "WhatWeb Fingerprint",
        "kind": "url",
        "base": ["whatweb"],
        "groups": [
            {
                "name": "Aggression",
                "options": [
                    {
                        "flag": "-a",
                        "type": "int",
                        "label": "Aggression level (-a)  [1=stealthy, 3=aggressive, 4=heavy]",
                        "default": 1,
                        "min": 1,
                        "max": 4
                    },
                ],
            },
    
            {
                "name": "HTTP options",
                "options": [
                    {"flag": "-U", "type": "str", "label": "User-Agent (-U)", "default": ""},
                    {"flag": "-H", "type": "str", "label": "Add header (-H)  (example: 'Foo: Bar')", "default": ""},
                    {"flag": "-H_AUTH", "type": "str", "label": "Bearer token (adds Authorization header)", "default": ""},
                    {
                        "flag": "--follow-redirect",
                        "type": "choice",
                        "label": "Follow redirects (--follow-redirect)",
                        "choices": ["never", "http-only", "meta-only", "same-site", "always"],
                        "default": "always"
                    },
                    {"flag": "--max-redirects", "type": "int", "label": "Max redirects (--max-redirects)", "default": 10, "min": 0, "max": 50},
                ],
            },
    
            {
                "name": "Authentication / Cookies",
                "options": [
                    {"flag": "-u", "type": "str", "label": "HTTP basic auth (-u)  (user:password)", "default": ""},
                    {"flag": "-c", "type": "str", "label": "Cookie (-c)  (example: 'name=value; name2=value2')", "default": ""},
                    {"flag": "--cookie-jar", "type": "str", "label": "Cookie jar (--cookie-jar)  (container path)", "default": ""},
                    {"flag": "--no-cookies", "type": "bool", "label": "Disable automatic cookie handling (--no-cookies)", "default": False},
                ],
            },
    
            {
                "name": "Proxy",
                "options": [
                    {"flag": "--proxy", "type": "str", "label": "Proxy host:port (--proxy)", "default": ""},
                    {"flag": "--proxy-user", "type": "str", "label": "Proxy user:pass (--proxy-user)", "default": ""},
                ],
            },
    
            {
                "name": "Plugins",
                "options": [
                    {"flag": "-l", "type": "bool", "label": "List all plugins (-l)", "default": False},
                    {"flag": "-I", "type": "str", "label": "Info plugins (-I) optional search term", "default": ""},
                    {"flag": "--search-plugins", "type": "str", "label": "Search plugins (--search-plugins)", "default": ""},
                    {"flag": "-p", "type": "str", "label": "Select plugins (-p)  (comma list, supports +/-)", "default": ""},
                    {"flag": "-g", "type": "str", "label": "Grep output (-g)  (string or /regex/)", "default": ""},
                    {"flag": "--custom-plugin", "type": "str", "label": "Custom plugin (--custom-plugin)", "default": ""},
                    {"flag": "--dorks", "type": "str", "label": "List Google dorks (--dorks)  (plugin name)", "default": ""},
                ],
            },
    
            {
                "name": "Output / Logging",
                "options": [
                    {"flag": "-v", "type": "bool", "label": "Verbose (-v)", "default": False},
                    {"flag": "-q", "type": "bool", "label": "Quiet (-q)", "default": False},
                    {"flag": "--no-errors", "type": "bool", "label": "Suppress error messages (--no-errors)", "default": False},
                    {
                        "flag": "--color",
                        "type": "choice",
                        "label": "Color output (--color)",
                        "choices": ["auto", "always", "never"],
                        "default": "auto"
                    },
    
                    {"flag": "--log-brief", "type": "str", "label": "Log brief (--log-brief)  (file path)", "default": ""},
                    {"flag": "--log-verbose", "type": "str", "label": "Log verbose (--log-verbose)  (file path)", "default": ""},
                    {"flag": "--log-errors", "type": "str", "label": "Log errors (--log-errors)  (file path)", "default": ""},
                    {"flag": "--log-xml", "type": "str", "label": "Log XML (--log-xml)  (file path)", "default": ""},
                    {"flag": "--log-json", "type": "str", "label": "Log JSON (--log-json)  (file path)", "default": ""},
                    {"flag": "--log-json-verbose", "type": "str", "label": "Log JSON verbose (--log-json-verbose)  (file path)", "default": ""},
                ],
            },
    
            {
                "name": "Performance & timeouts",
                "options": [
                    {"flag": "-t", "type": "int", "label": "Max threads (-t)", "default": 25, "min": 1, "max": 200},
                    {"flag": "--open-timeout", "type": "int", "label": "Open timeout seconds (--open-timeout)", "default": 15, "min": 1, "max": 300},
                    {"flag": "--read-timeout", "type": "int", "label": "Read timeout seconds (--read-timeout)", "default": 30, "min": 1, "max": 600},
                    {"flag": "--wait", "type": "int", "label": "Wait between connections seconds (--wait)", "default": 0, "min": 0, "max": 60},
                ],
            },
        ],
    },
    "subfinder": {
        "title": "subfinder",
        "kind": "domain",
        "base": ["subfinder"],
        "groups": [
            {
                "name": "Targets",
                "options": [
                    {"flag": "-d", "type": "str", "label": "Domain (-d) (optional override)", "default": ""},
                    {"flag": "-dL", "type": "str", "label": "Domain list file (-dL) (container path)", "default": ""},
                ],
            },
    
            {
                "name": "Sources",
                "options": [
                    {"flag": "-s", "type": "str", "label": "Specific sources (-s) (comma list: crtsh,github)", "default": ""},
                    {"flag": "-es", "type": "str", "label": "Exclude sources (-es) (comma list: alienvault,zoomeye)", "default": ""},
                    {"flag": "-recursive", "type": "bool", "label": "Recursive sources only (-recursive)", "default": False},
                    {"flag": "-all", "type": "bool", "label": "Use all sources (-all) (slow)", "default": False},
                    {"flag": "-ls", "type": "bool", "label": "List available sources (-ls)", "default": False},
                ],
            },
    
            {
                "name": "Filtering / Matching",
                "options": [
                    {"flag": "-m", "type": "str", "label": "Match (-m) (subdomain / file / comma list)", "default": ""},
                    {"flag": "-f", "type": "str", "label": "Filter (-f) (subdomain / file / comma list)", "default": ""},
                    {"flag": "-ei", "type": "str", "label": "Exclude IPs (-ei) (comma list)", "default": ""},
                ],
            },
    
            {
                "name": "Resolvers / Performance",
                "options": [
                    {"flag": "-rl", "type": "int", "label": "Rate limit (-rl) requests/sec", "default": 0, "min": 0, "max": 10000},
                    {"flag": "-timeout", "type": "int", "label": "Timeout seconds (-timeout)", "default": 30, "min": 1, "max": 600},
                    {"flag": "-max-time", "type": "int", "label": "Max time minutes (-max-time)", "default": 10, "min": 1, "max": 120},
    
                    {"flag": "-r", "type": "str", "label": "Resolvers (-r) (comma list)", "default": ""},
                    {"flag": "-rL", "type": "str", "label": "Resolvers file (-rL) (container path)", "default": ""},
                ],
            },
    
            {
                "name": "Active / IP options",
                "options": [
                    {"flag": "-nW", "type": "bool", "label": "Active mode (-nW) (active subdomains only)", "default": False},
                    {"flag": "-t", "type": "int", "label": "Goroutines (-t) (active only)", "default": 10, "min": 1, "max": 500},
                    {"flag": "-oI", "type": "bool", "label": "Include host IP (-oI) (active only)", "default": False},
                ],
            },
    
            {
                "name": "Output / Logging",
                "options": [
                    {"flag": "-silent", "type": "bool", "label": "Silent output (-silent)", "default": True},
                    {"flag": "-v", "type": "bool", "label": "Verbose (-v)", "default": False},
                    {"flag": "-nc", "type": "bool", "label": "No color (-nc)", "default": False},
    
                    {"flag": "-o", "type": "str", "label": "Output file (-o) (container path)", "default": ""},
                    {"flag": "-oD", "type": "str", "label": "Output directory (-oD) (dL only)", "default": ""},
                    {"flag": "-oJ", "type": "bool", "label": "JSONL output (-oJ)", "default": False},
                    {"flag": "-cs", "type": "bool", "label": "Collect sources (-cs) (json only)", "default": False},
                ],
            },
    
            {
                "name": "Config / Proxy",
                "options": [
                    {"flag": "-config", "type": "str", "label": "Config file (-config) (container path)", "default": ""},
                    {"flag": "-pc", "type": "str", "label": "Provider config (-pc) (container path)", "default": ""},
                    {"flag": "-proxy", "type": "str", "label": "HTTP proxy (-proxy)", "default": ""},
                ],
            },
    
            {
                "name": "Info",
                "options": [
                    {"flag": "-version", "type": "bool", "label": "Show version (-version)", "default": False},
                ],
            },
        ],
    },
    "wafw00f": {
        "title": "WAF Detection (WAFW00F)",
        "kind": "url",
        "base": ["wafw00f"],
        "groups": [
            {
                "name": "Basics",
                "options": [
                    {"flag": "-a", "type": "bool", "label": "Find all matching WAFs (-a / --findall)", "default": False},
                    {"flag": "-r", "type": "bool", "label": "Do not follow redirects (-r / --noredirect)", "default": False},
                    {"flag": "-v", "type": "count", "label": "Verbosity level (-v, repeatable)", "default": 0},
                    {"flag": "--no-colors", "type": "bool", "label": "Disable ANSI colors (--no-colors)", "default": True},
                ],
            },
    
            {
                "name": "Target Control",
                "options": [
                    {"flag": "-t", "type": "str", "label": "Test one specific WAF (-t / --test)", "default": ""},
                    {"flag": "-i", "type": "str", "label": "Input file of targets (-i / --input-file) (container path)", "default": ""},
                    {"flag": "-l", "type": "bool", "label": "List detectable WAFs (-l / --list)", "default": False},
                ],
            },
    
            {
                "name": "Networking",
                "options": [
                    {"flag": "-p", "type": "str", "label": "Proxy (-p / --proxy) (http://host:8080 or socks5://...)", "default": ""},
                    {"flag": "-T", "type": "int", "label": "Timeout seconds (-T / --timeout)", "default": 15, "min": 1, "max": 600},
                ],
            },
    
            {
                "name": "Output",
                "options": [
                    {"flag": "-o", "type": "str", "label": "Write output file (-o / --output) (csv/json/txt by extension)", "default": ""},
                    {"flag": "-f", "type": "choice", "label": "Force output format (-f / --format)", "choices": ["csv", "json", "text"], "default": ""},
                ],
            },
    
            {
                "name": "Headers",
                "options": [
                    {"flag": "-H", "type": "str", "label": "Headers file (-H / --headers) (container path)", "default": ""},
                ],
            },
    
            {
                "name": "Info",
                "options": [
                    {"flag": "-V", "type": "bool", "label": "Print version (-V / --version)", "default": False},
                ],
            },
        ],
    },
}

def iter_tool_options(tool: dict):
    if "groups" in tool:
        for g in tool["groups"]:
            for opt in g.get("options", []):
                yield opt
    else:
        for opt in tool.get("options", []):
            yield opt


def safe_report_filename(domain: str, ext: str = "html") -> str:
    base = (domain or "").lower().replace("www.", "")
    base = re.sub(r"[^a-z0-9.-]+", "-", base).strip("-.")
    if not base:
        base = "report"

    ts = datetime.now().strftime("%m-%d-%Y-%H%M")
    return f"{base}-{ts}.{ext}"

def get_tools_list():
    return [{"id": k, "title": v["title"]} for k, v in TOOL_DEFS.items()]

def get_tool(tool_id: str):
    if tool_id not in TOOL_DEFS:
        raise KeyError("Unknown tool")
    return TOOL_DEFS[tool_id]

def build_tool_command(tool_id: str, domain: str, url: str, selected: dict) -> list[str]:
    tool = get_tool(tool_id)
    args = list(tool["base"])

    for opt in iter_tool_options(tool):
        flag = opt["flag"]
        typ = opt["type"]
        key = flag 
        if tool_id == "dig":
            if opt["flag"] == "@":
                v = (selected.get("@") or "").strip()
                if v:
                    args.insert(1, f"@{v}")
                continue
                
        if tool_id == "wafw00f":
            if selected.get("-l") in (True, "true", "on", "1", 1):
                return args  
            infile = (selected.get("-i") or "").strip()
            if infile:
                return args 
        
        if opt["flag"] == "-H_AUTH":
            token = (selected.get("-H_AUTH") or "").strip()
            if token:
                args += ["-H", f"Authorization: Bearer {token}"]
            continue

        if tool_id == "subfinder":
            dl = (selected.get("-dL") or "").strip()
            d = (selected.get("-d") or "").strip()
            if dl:
                return args  
            if d:
                args.append(d)
                return args  
        
        if tool_id == "curl" and opt["flag"] == "-H_AUTH":
            token = (selected.get("-H_AUTH") or "").strip()
            if token:
                args += ["-H", f"Authorization: Bearer {token}"]
            continue
        
        

        if typ == "bool":
            if selected.get(key) in (True, "true", "on", "1", 1):
                args.append(flag)

        elif typ == "int":
            raw = selected.get(key)
            if raw in (None, "", 0, "0"):
                continue
            try:
                val = int(raw)
            except:
                continue
            mn = opt.get("min")
            mx = opt.get("max")
            if mn is not None and val < mn:
                val = mn
            if mx is not None and val > mx:
                val = mx
            args += [flag, str(val)]
            
        elif typ == "choice":
            raw = (selected.get(key) or "").strip()
            if raw:
                args.append(raw)
        
        elif typ == "count":
            raw = selected.get(flag)
            try:
                val = int(raw) if raw not in (None, "", "0") else 0
            except:
                val = 0
            if val > 0:
                args.append(flag + (flag[-1] * (val - 1)))
                
        elif typ in ("str_kv", "choice_kv"):
            raw = (selected.get(key) or "").strip()
            if raw:
                args.append(f"{flag}{raw}" if flag.endswith("=") else f"{flag}={raw}")
        
        elif typ == "int_kv":
            raw = selected.get(key)
            if raw not in (None, "", "0", 0):
                try:
                    val = int(raw)
                except:
                    val = None
                if val is not None:
                    args.append(f"{flag}{val}" if flag.endswith("=") else f"{flag}={val}")
        
        
        

        elif typ == "str":
            raw = (selected.get(key) or "").strip()
            if not raw:
                continue
            args += [flag, raw]

    if tool["kind"] == "domain":
        args.append(domain)
    else:
        args.append(url)
    
    server = (selected.get("__server__") or "").strip()
    if tool_id == "nslookup" and server:
        args.append(server)
    
    return args
    

def run_single_tool(target: str, tool_id: str, selected: dict) -> dict:
    domain = normalize_target(target)
    if not domain:
        raise ValueError("Target is empty or invalid.")
    url = target.strip()
    if "://" not in url:
        url = "https://" + url
    

    cmd = build_tool_command(tool_id, domain=domain, url=url, selected=selected)
    title = TOOL_DEFS[tool_id]["title"]
    output = run_cmd(cmd, timeout=90)

    if title.startswith("Subdomain Enumeration") and not output.strip():
        output = "No subdomains found.\n"

    return {
        "target": target,
        "domain": domain,
        "section": {"title": title, "command": " ".join(cmd), "output": output},
    }


def build_data_uri_for_logo(logo_path: Path) -> str | None: 
  try: 
    data = logo_path.read_bytes() 
  except FileNotFoundError: 
    return None 

  mime, _ = mimetypes.guess_type(str(logo_path)) 
  if not mime: 
    mime = "image/png" 

  b64 = base64.b64encode(data).decode("ascii") 
  return f"data:{mime};base64,{b64}"

def detect_wildcard_length(domain: str) -> int | None:
    fake_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    url = f"https://{domain}/{fake_path}"
    out = run_cmd(["curl", "-s", "-o", "/dev/null", "-w", "%{size_download}", url], timeout=20).strip()
    try:
        return int(out)
    except:
        return None

def detect_wildcard_status(domain: str) -> int | None:
    fake_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    url = f"https://{domain}/{fake_path}"
    out = run_cmd(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url], timeout=20).strip()
    try:
        return int(out)
    except:
        return None


def normalize_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "https://" + t
    parsed = urlparse(t)
    domain = parsed.netloc or parsed.path
    return domain.strip().strip("/")


def run_cmd(args, timeout=90) -> str:
    try:
        out = subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode(errors="replace")
    except FileNotFoundError:
        return f"[!] Tool not installed: {args[0]}\n"
    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s: {' '.join(args)}\n"
    except subprocess.CalledProcessError as e:
        return f"[!] Error running: {' '.join(args)}\n{e.output.decode(errors='replace')}\n"


def build_tools(domain: str):
    url = f"https://{domain}"

    wild_len = detect_wildcard_length(domain)
    wild_code = detect_wildcard_status(domain)

    gobuster_args = ["gobuster", "dir", "-u", url, "-w", "./common.txt", "-f"]

    if wild_len is not None and wild_len > 0:
        gobuster_args += ["--exclude-length", str(wild_len)]
    else:
        if wild_code is not None and wild_code not in (404,):
            gobuster_args += ["-b", str(wild_code)]
        else:
            gobuster_args += ["-b", "404"]

    return [
        (["whois", domain.replace("www.", "")], "WHOIS Lookup"),
        (["nslookup", domain], "NSLookup"),
        (["dig", domain], "DIG DNS Info"),
        (["nmap", "-F", domain], "Nmap Fast Scan"),
        (["curl", "-I", url], "HTTP Headers (curl)"),
        (["whatweb", url], "WhatWeb Fingerprint"),
        (["subfinder", "-silent", "-d", domain], "Subdomain Enumeration (subfinder)"),
        (gobuster_args, "Gobuster Directory Scan"),
        (["wafw00f", url], "WAF Detection (WAFW00F)"),
    ]

def render_report_html(target: str, domain: str, sections: list[dict]) -> str:
    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report_template.html")

    logo_data_uri = build_data_uri_for_logo(Path("static") / "SaberShieldLogoWithText.png")

    return template.render(
        target=target,
        domain=domain,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        sections=sections,
        logo_data_uri=logo_data_uri,
    )


def run_recon_and_write_html(target: str, output_html_path: Path, progress_cb=None) -> None:
    domain = normalize_target(target)
    if not domain:
        raise ValueError("Target is empty or invalid.")

    tools = build_tools(domain)
    total = len(tools)

    sections = []
    for i, (args, title) in enumerate(tools, start=1):
        if progress_cb:
            progress_cb({
                "percent": int(((i - 1) / total) * 100),
                "stage": f"Running: {title}",
                "current": i - 1,
                "total": total,
            })

        output = run_cmd(args, timeout=90)
        if title.startswith("Subdomain Enumeration") and not output.strip():
            output = "No subdomains found.\n"

        sections.append({"title": title, "command": " ".join(args), "output": output})

        if progress_cb:
            progress_cb({
                "percent": int((i / total) * 100),
                "stage": f"Completed: {title}",
                "current": i,
                "total": total,
            })

    html = render_report_html(target=target, domain=domain, sections=sections)
    output_html_path.write_text(html)

    if progress_cb:
        progress_cb({
            "percent": 100,
            "stage": "Done",
            "current": total,
            "total": total,
        })

