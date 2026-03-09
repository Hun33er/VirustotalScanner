# -*- coding: utf-8 -*-
# VirusTotal Scope Extractor - Burp Suite Extension
# Language: Python (Jython 2.7)
#
# Installation:
#   1. Extender > Options > Python Environment -> set Jython standalone JAR path
#   2. Extender > Extensions > Add -> Type: Python -> load this file
#
# Usage:
#   - Find a VirusTotal API response in Proxy / Repeater / HTTP History
#   - Right-click it -> Extensions -> Send to VT Scope Extractor
#   - Results appear in the "VT Scope" tab
#   - Select rows and click "Selected -> Scope" or "Selected -> Site Map"

from burp import (IBurpExtender, ITab, IHttpRequestResponse,
                  IContextMenuFactory)
from javax.swing import (JPanel, JScrollPane, JTextArea, JButton, JLabel,
                         JSplitPane, JTable, JCheckBox, BorderFactory,
                         SwingUtilities, JOptionPane, JMenuItem)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Font, FlowLayout
from java.util import ArrayList
import java.net.URL as JavaURL
import json
import random
from urlparse import urlparse

# --------------------------------------------------------------------------- #
#  User-Agent pool - one is picked at random per site-map request             #
# --------------------------------------------------------------------------- #
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/109.0.0.0",
]


# --------------------------------------------------------------------------- #
#  Non-editable table model                                                    #
# --------------------------------------------------------------------------- #
class _ReadOnlyTableModel(DefaultTableModel):
    def __init__(self, columns, rows):
        DefaultTableModel.__init__(self, columns, rows)

    def isCellEditable(self, row, col):
        return False


# --------------------------------------------------------------------------- #
#  Minimal IHttpRequestResponse for site-map injection                        #
# --------------------------------------------------------------------------- #
class _SiteMapEntry(IHttpRequestResponse):
    def __init__(self, service, request_bytes, response_bytes):
        self._service  = service
        self._request  = request_bytes
        self._response = response_bytes

    def getRequest(self):         return self._request
    def setRequest(self, m):      self._request = m
    def getResponse(self):        return self._response
    def setResponse(self, m):     self._response = m
    def getComment(self):         return "VT Scope Extractor"
    def setComment(self, c):      pass
    def getHighlight(self):       return "yellow"
    def setHighlight(self, c):    pass
    def getHttpService(self):     return self._service
    def setHttpService(self, s):  self._service = s


# --------------------------------------------------------------------------- #
#  Main extension class                                                        #
# --------------------------------------------------------------------------- #
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    # ----------------------------------------------------------------------- #
    #  IBurpExtender                                                           #
    # ----------------------------------------------------------------------- #
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("VT Scope Extractor")

        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()

        SwingUtilities.invokeLater(self._build_ui)

        # Register right-click context menu
        callbacks.registerContextMenuFactory(self)

        self._print("VT Scope Extractor loaded.")
        self._print("Right-click any VT API response -> Send to VT Scope Extractor")

    # ----------------------------------------------------------------------- #
    #  ITab                                                                    #
    # ----------------------------------------------------------------------- #
    def getTabCaption(self):
        return "VT Scope"

    def getUiComponent(self):
        return self._panel

    # ----------------------------------------------------------------------- #
    #  IContextMenuFactory - right-click menu                                 #
    # ----------------------------------------------------------------------- #
    def createMenuItems(self, invocation):
        context = invocation.getInvocationContext()

        # Show menu in Proxy, Repeater, Target, HTTP History, etc.
        allowed = [
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_SCANNER_RESULTS,
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE,
        ]
        if context not in allowed:
            return None

        menu_items = ArrayList()
        item = JMenuItem("Send to VT Scope Extractor")

        # Capture invocation for the lambda
        inv = invocation

        def on_click(event):
            messages = inv.getSelectedMessages()
            if messages:
                for msg in messages:
                    self._process_message(msg)

        item.addActionListener(on_click)
        menu_items.add(item)
        return menu_items

    # ----------------------------------------------------------------------- #
    #  Process a manually sent message                                        #
    # ----------------------------------------------------------------------- #
    def _process_message(self, messageInfo):
        response = messageInfo.getResponse()
        if not response:
            self._print("[!] No response in selected message.")
            return

        # Check it is a VT API call
        req_info = self._helpers.analyzeRequest(messageInfo)
        url      = str(req_info.getUrl())

        vt_endpoints = [
            "/vtapi/v2/domain/report",
            "/vtapi/v2/url/report",
            "/vtapi/v2/ip-address/report",
        ]
        is_vt = "virustotal.com" in url.lower() and any(ep in url for ep in vt_endpoints)

        if not is_vt:
            self._print("[!] Selected request is not a recognised VT API endpoint.")
            self._print("    URL was: " + url)
            self._print("    Trying to parse response anyway...")

        # Parse JSON body from response
        resp_info   = self._helpers.analyzeResponse(response)
        body_offset = resp_info.getBodyOffset()
        body_str    = self._helpers.bytesToString(response[body_offset:])

        try:
            vt_json = json.loads(body_str)
        except Exception as e:
            self._print("[!] Could not parse JSON: " + str(e))
            return

        extracted = self._extract_from_response(vt_json)

        total = len(extracted["domains"]) + len(extracted["urls"]) + len(extracted["ips"])
        if total == 0:
            self._print("[!] Nothing extracted from response body.")
            return

        self._print("\n[+] Extracted from: " + url)
        self._print("    Domains/Subdomains : " + str(len(extracted["domains"])))
        self._print("    URLs               : " + str(len(extracted["urls"])))
        self._print("    IP Addresses       : " + str(len(extracted["ips"])))

        self._update_table(extracted, url)

    # ----------------------------------------------------------------------- #
    #  Extraction - VT response JSON body ONLY                                #
    # ----------------------------------------------------------------------- #
    def _extract_from_response(self, data):
        domains = set()
        urls    = set()
        ips     = set()

        # subdomains []
        for item in data.get("subdomains", []):
            v = str(item).strip()
            if v:
                domains.add(v)

        # domain_siblings []
        for item in data.get("domain_siblings", []):
            v = str(item).strip()
            if v:
                domains.add(v)

        # detected_urls -> list of dicts {"url": "...", ...}
        for item in data.get("detected_urls", []):
            raw = item.get("url", "").strip()
            if raw:
                urls.add(raw)
                host = self._hostname(raw)
                if host:
                    domains.add(host)

        # undetected_urls -> list of lists [url, hash, positives, total, date]
        for item in data.get("undetected_urls", []):
            if isinstance(item, list) and len(item) > 0:
                raw = str(item[0]).strip()
            elif isinstance(item, dict):
                raw = item.get("url", "").strip()
            else:
                raw = ""
            if raw:
                urls.add(raw)
                host = self._hostname(raw)
                if host:
                    domains.add(host)

        # resolutions -> ip_address (domain report) or hostname (IP report)
        for item in data.get("resolutions", []):
            ip = item.get("ip_address", "").strip()
            if ip:
                ips.add(ip)
            hostname = item.get("hostname", "").strip()
            if hostname:
                domains.add(hostname)

        return {
            "domains": sorted(domains),
            "urls":    sorted(urls),
            "ips":     sorted(ips),
        }

    def _hostname(self, raw_url):
        try:
            return urlparse(raw_url).hostname or ""
        except:
            return ""

    # ----------------------------------------------------------------------- #
    #  Add to Burp Scope                                                       #
    # ----------------------------------------------------------------------- #
    def _add_to_scope(self, extracted):
        added = 0

        for domain in extracted["domains"]:
            for scheme in ["https", "http"]:
                try:
                    u = JavaURL(scheme + "://" + domain)
                    if not self._callbacks.isInScope(u):
                        self._callbacks.includeInScope(u)
                        self._print("  [scope+] " + scheme + "://" + domain)
                        added += 1
                except Exception as e:
                    self._print("  [scope err] " + domain + " -> " + str(e))

        for raw in extracted["urls"]:
            try:
                u = JavaURL(raw)
                if not self._callbacks.isInScope(u):
                    self._callbacks.includeInScope(u)
                    self._print("  [scope+] " + raw)
                    added += 1
            except Exception as e:
                self._print("  [scope err] " + raw + " -> " + str(e))

        for ip in extracted["ips"]:
            for scheme in ["https", "http"]:
                try:
                    u = JavaURL(scheme + "://" + ip)
                    if not self._callbacks.isInScope(u):
                        self._callbacks.includeInScope(u)
                        self._print("  [scope+] " + scheme + "://" + ip)
                        added += 1
                except Exception as e:
                    self._print("  [scope err] " + ip + " -> " + str(e))

        self._print("  => " + str(added) + " entries added to scope.")

    # ----------------------------------------------------------------------- #
    #  Send to Site Map - uses the exact Value from the table row             #
    # ----------------------------------------------------------------------- #
    def _send_to_sitemap(self, extracted):
        """
        Sends the exact extracted value to Burp's Site Map.
        - Domain/Sub  -> https://<value>/
        - URL         -> parsed directly as-is
        - IP          -> https://<value>/
        """
        added = 0

        def _make_req(host, path):
            ua = random.choice(USER_AGENTS)
            return self._helpers.stringToBytes(
                "GET " + path + " HTTP/1.1\r\n" +
                "Host: " + host + "\r\n" +
                "User-Agent: " + ua + "\r\n" +
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
                "Accept-Language: en-US,en;q=0.5\r\n" +
                "Connection: close\r\n\r\n"
            )

        def _make_resp(value):
            body = "VT Scope Extractor | " + value
            return self._helpers.stringToBytes(
                "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/plain\r\n" +
                "Content-Length: " + str(len(body)) + "\r\n\r\n" +
                body
            )

        def _inject(host, path, port, use_ssl, value):
            try:
                svc   = self._helpers.buildHttpService(host, port, use_ssl)
                entry = _SiteMapEntry(svc, _make_req(host, path), _make_resp(value))
                self._callbacks.addToSiteMap(entry)
                scheme = "https" if use_ssl else "http"
                self._print("  [sitemap+] " + scheme + "://" + host + path)
                return True
            except Exception as e:
                self._print("  [sitemap err] " + value + " -> " + str(e))
                return False

        # Domains and IPs: use the exact value string as the host
        for domain in extracted["domains"]:
            if _inject(domain, "/", 443, True, domain):
                added += 1

        for ip in extracted["ips"]:
            if _inject(ip, "/", 443, True, ip):
                added += 1

        # URLs: parse the exact value to get host/path/port/scheme
        for raw in extracted["urls"]:
            try:
                p       = urlparse(raw)
                host    = p.hostname or ""
                path    = p.path or "/"
                if p.query:
                    path += "?" + p.query
                use_ssl = (p.scheme.lower() == "https")
                port    = p.port or (443 if use_ssl else 80)
                if host and _inject(host, path, port, use_ssl, raw):
                    added += 1
            except Exception as e:
                self._print("  [sitemap err] " + raw + " -> " + str(e))

        self._print("  => " + str(added) + " entries sent to site map.")

    # ----------------------------------------------------------------------- #
    #  UI                                                                      #
    # ----------------------------------------------------------------------- #
    def _build_ui(self):
        self._panel = JPanel(BorderLayout())

        # ---- Toolbar --------------------------------------------------
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        toolbar.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4))

        title = JLabel("VirusTotal Scope Extractor")
        title.setFont(Font("SansSerif", Font.BOLD, 13))
        toolbar.add(title)

        btn_scope   = JButton("Selected -> Scope")
        btn_sitemap = JButton("Selected -> Site Map")
        btn_both    = JButton("Selected -> Scope + Site Map")
        btn_clear   = JButton("Clear")

        btn_scope.addActionListener(  lambda e: self._manual_action("scope"))
        btn_sitemap.addActionListener(lambda e: self._manual_action("sitemap"))
        btn_both.addActionListener(   lambda e: self._manual_action("both"))
        btn_clear.addActionListener(  lambda e: self._clear_table())

        for btn in [btn_scope, btn_sitemap, btn_both, btn_clear]:
            toolbar.add(btn)

        self._panel.add(toolbar, BorderLayout.NORTH)

        # ---- Table ----------------------------------------------------
        self._table_model = _ReadOnlyTableModel(
            ["Type", "Value", "VT Response Source"], 0
        )
        self._table = JTable(self._table_model)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        self._table.getColumnModel().getColumn(0).setPreferredWidth(90)
        self._table.getColumnModel().getColumn(1).setPreferredWidth(340)
        self._table.getColumnModel().getColumn(2).setPreferredWidth(440)
        self._table.setFillsViewportHeight(True)

        tbl_scroll = JScrollPane(self._table)

        # ---- Log area -------------------------------------------------
        self._log = JTextArea(7, 80)
        self._log.setEditable(False)
        self._log.setFont(Font("Monospaced", Font.PLAIN, 11))
        log_scroll = JScrollPane(self._log)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, tbl_scroll, log_scroll)
        split.setResizeWeight(0.75)
        self._panel.add(split, BorderLayout.CENTER)

        self._callbacks.addSuiteTab(self)

    # ---- Table helpers -----------------------------------------------
    def _update_table(self, extracted, source_url):
        def _run():
            for d in extracted["domains"]:
                self._table_model.addRow(["Domain/Sub", d, source_url])
            for u in extracted["urls"]:
                self._table_model.addRow(["URL", u, source_url])
            for ip in extracted["ips"]:
                self._table_model.addRow(["IP", ip, source_url])
        SwingUtilities.invokeLater(_run)

    def _clear_table(self):
        self._table_model.setRowCount(0)

    def _get_selected(self):
        rows = self._table.getSelectedRows()
        if not rows:
            JOptionPane.showMessageDialog(
                self._panel,
                "Please select one or more rows first.",
                "VT Scope Extractor",
                JOptionPane.INFORMATION_MESSAGE
            )
            return None
        domains, urls, ips = [], [], []
        for r in rows:
            t = str(self._table_model.getValueAt(r, 0))
            v = str(self._table_model.getValueAt(r, 1))
            if t == "Domain/Sub": domains.append(v)
            elif t == "URL":      urls.append(v)
            elif t == "IP":       ips.append(v)
        return {"domains": domains, "urls": urls, "ips": ips}

    def _manual_action(self, action):
        ex = self._get_selected()
        if not ex:
            return
        if action in ("scope", "both"):
            self._add_to_scope(ex)
        if action in ("sitemap", "both"):
            self._send_to_sitemap(ex)

    # ----------------------------------------------------------------------- #
    #  Logging                                                                 #
    # ----------------------------------------------------------------------- #
    def _print(self, msg):
        try:
            self._stdout.write((msg + "\n").encode("utf-8"))
        except:
            pass
        def _append():
            self._log.append(msg + "\n")
            self._log.setCaretPosition(self._log.getDocument().getLength())
        try:
            SwingUtilities.invokeLater(_append)
        except:
            pass
