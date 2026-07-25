# luci-app-mod-dashboard

![Version](https://img.shields.io/badge/version-1.0.0-purple.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![OpenWrt](https://img.shields.io/badge/OpenWrt-21.02+-orange.svg)

A fresh installation of OpenWrt 25.x does not come with a built-in visual firewall intelligence dashboard out of the box. This lightweight package bridges that gap by adding a real-time tracking interface directly into your LuCI web UI—letting you visualize dropped and allowed packets, identify top offending IPs, and monitor triggered firewall rules straight from your router without heavy backend databases.

## Features

🔍 **Search & Forensics**
* Smart Multi-Term Search: You can type multiple words (like DROP 192.168.1.31 UDP) and it filters down to rows matching all those terms.
* Time Range Filtering: Type 10:20:00 - 10:30:00 in the search bar to isolate traffic from a specific window.
* Stackable Click-to-Search: Clicking on any row data (IPs, Actions, Rules) or Leaderboard items instantly adds that word to your search bar, stacking them together for rapid forensic narrowing.

📊 **Real-Time Analytics**
* Live Leaderboards: Four dynamic lists automatically track and rank the Top Rules Hit, Top Source IPs, Top Target IPs, and Top Ports.
* Live Polling: The system silently reads dmesg every couple of seconds and injects new logs into your dashboard instantly.
* External IP Lookups: Clicking any public IP address opens a new tab to ipinfo.io so you can instantly see who owns that IP and where it is located.

💻 **Data Handling & UI**
* Pagination: Prevents browser lag by organizing massive log dumps into fast-loading pages of 100 items each, complete with ◀ and ▶ controls.
* Full MAC Address Display: Shows the complete, uncut MAC address underneath the source IP.
* Pause/Resume Feed: A toggle button to freeze incoming logs so you can read fast-moving data without it jumping around.
* Export to CSV: One-click download of whatever is currently on your screen (respecting your search filters) into a spreadsheet file for offline auditing.
* Clear Logs (Soft Clear): A panic button that hides all previous logs from your screen instantly, letting you start with a clean slate from that exact second onward.
* Action Badging: Color-coded tags for Actions (Green for ALLOW, Red for DROP, Orange for REJECT) for quick visual scanning.

⚠️ **IMPORTANT NOTE: Log Buffer & History**
* Limited Historical Scope: While this dashboard provides a searchable history, it is not a long-term forensic log solution. It parses and displays only the most recent 10,000 lines of the system dmesg buffer.
* Dynamic Search: The dashboard allows you to filter and inspect this 10,000-line window in real-time, making it an excellent tool for active troubleshooting and immediate traffic auditing.
* Data Persistence: Because this tool reads directly from the volatile dmesg ring buffer, logs older than the current 10,000-line capture limit will be overwritten by new system events and will no longer be accessible via this interface.
---

## Installation

### Prerequisites
* OpenWrt 25.x or later
* Enable logging on your Firewall Rule under Network -> Firewall -> Traffic Rules
* <img width="519" height="72" alt="image" src="https://github.com/user-attachments/assets/4d1d610f-91fc-429e-99e5-cf679043b156" />
* LuCI web interface installed
* SSH access to your router

#### 1. Create Directory Structure
This Creates an isolated, dedicated folder for your custom dashboard frontend code. This keeps it separate from other LuCI apps so nothing conflicts.
```bash
mkdir -p /www/luci-static/resources/view/dashboard
```

#### 2. Register "Dashboard" LuCi Menu
```bash
cat << 'EOF' > /usr/share/luci/menu.d/luci-app-joeddashboard.json
```
Paste the following:
```bash
{
        "admin/dashboard": {
                "title": "Dashboard",
                "order": 1,
                "action": {
                        "type": "view",
                        "path": "dashboard/index"
                },
                "depends": {
                        "acl": [ "luci-app-joeddashboard" ]
                }
        }
}
EOF
```
#### 3. Setup ACL Permissions
This Acts as the security gatekeeper for OpenWrt's rpcd daemon. Without this, LuCI hides the tab and blocks access even for the root user.
```bash
cat << 'EOF' > /usr/share/rpcd/acl.d/luci-app-joeddashboard.json
```
Paste the following:
```bash
{
        "luci-app-joeddashboard": {
                "description": "Access to Joed Dashboard",
                "read": {
                        "uci": [ "*" ],
                        "file": {
                                "/proc/uptime": [ "read" ]
                        }
                },
                "write": {
                        "file": {
                                "/bin/dmesg": [ "exec" ]
                        }
                }
        }
}
EOF
```
#### 4. Add the Frontend Code
The client-side JavaScript that renders in your browser.
```bash
cat << 'EOF' > /www/luci-static/resources/view/dashboard/index.js
```
Paste the following:
```bash
'use strict';
'require view';
'require fs';
'require poll';

return view.extend({
    isPaused: false,
    clear_ts: 0,
    currentFilteredItems: [],
    currentPage: 0,
    pageSize: 100,

    // Generalized parser to extract all key details from dmesg
    parseLogLine: function(line) {
        var match = line.match(/^\[\s*([\d\.]+)\]\s+(.*?):\s+(.*)$/);
        if (!match) return null;

        var ts = parseFloat(match[1]);
        var rule = match[2].trim();
        var payload = match[3];

        var kv = {};
        payload.replace(/([A-Z]+)=([^\s]+)/g, function(m, key, val) {
            kv[key] = val;
        });

        var action = 'DROP';
        var rLower = rule.toLowerCase();
        if (rLower.indexOf('allow') > -1 || rLower.indexOf('accept') > -1 || rLower.indexOf('pass') > -1) action = 'ALLOW';
        else if (rLower.indexOf('reject') > -1) action = 'REJECT';

        var proto = kv.PROTO || '-';
        var protoMap = { 
            '1': 'ICMP', '2': 'IGMP', '6': 'TCP', '17': 'UDP', 
            '47': 'GRE', '50': 'ESP', '51': 'AH', '89': 'OSPF'
        };
        
        var portMap = { 
            '20': 'FTP', '21': 'FTP', '22': 'SSH', '23': 'TELNET', 
            '25': 'SMTP', '53': 'DNS', '67': 'DHCP', '68': 'DHCP', 
            '80': 'HTTP', '123': 'NTP', '443': 'HTTPS', '500': 'IKE', '4500': 'IPSEC' 
        };

        if (protoMap[proto]) {
            proto = protoMap[proto];
        } else if (/^\d+$/.test(proto)) {
            proto = 'PROTO-' + proto; 
        }

        var fmtPort = function(p) {
            if (!p) return '';
            return ':' + p + (portMap[p] ? ' (' + portMap[p] + ')' : '');
        };

        return {
            ts: ts,
            rule: rule,
            action: action,
            inFace: kv.IN || '-',
            src: kv.SRC || '-',
            dst: kv.DST || '-',
            proto: proto,
            spt: fmtPort(kv.SPT),
            dpt: fmtPort(kv.DPT),
            macOrig: kv.MAC || ''
        };
    },

    // Helper to generate a scrollable, dynamic leaderboard card
    generateTopList: function(statObj, title, searchInput) {
        var sorted = Object.keys(statObj).sort(function(a, b) {
            return statObj[b] - statObj[a];
        }); 

        var listItems = sorted.map(function(key) {
            var row = E('div', { 'style': 'display: flex; justify-content: space-between; margin-bottom: 8px; border-bottom: 1px solid #333; padding-bottom: 5px; cursor: pointer; transition: background 0.2s;' }, [
                E('span', { 'style': 'font-family: monospace; font-size: 13px; color: #ddd;' }, key),
                E('strong', { 'style': 'color: #38bdf8; background: #0f172a; padding: 2px 8px; border-radius: 12px; font-size: 12px;' }, statObj[key])
            ]);

            row.addEventListener('mouseenter', function() { this.style.background = '#27272a'; });
            row.addEventListener('mouseleave', function() { this.style.background = 'transparent'; });
            
            row.addEventListener('click', function() {
                if (searchInput) {
                    var termToAdd = key.replace(/\s*\(.*\)$/, ''); // Strip port names like (DNS)
                    var currentTokens = searchInput.value.trim().toLowerCase().split(/\s+/);
                    var newTokens = termToAdd.toLowerCase().split(/\s+/);
                    
                    // Only append if the term isn't already part of the current search
                    var alreadyHasTerm = newTokens.every(function(t) { return currentTokens.indexOf(t) !== -1; });
                    
                    if (!alreadyHasTerm || searchInput.value.trim() === '') {
                        searchInput.value = (searchInput.value.trim() + ' ' + termToAdd).trim();
                    }
                    searchInput.dispatchEvent(new Event('input')); 
                }
            });

            return row;
        });

        if (listItems.length === 0) {
            listItems = [ E('div', { 'style': 'color: #666; font-style: italic; font-size: 13px; text-align: center; padding: 10px 0;' }, 'Awaiting traffic data...') ];
        }

        return E('div', { 'style': 'flex: 1; min-width: 220px; background: #1e1e1e; border: 1px solid #333; border-radius: 8px; padding: 15px; margin: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.3);' }, [
            E('h4', { 'style': 'margin-top: 0; color: #f8fafc; border-bottom: 2px solid #38bdf8; padding-bottom: 8px; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 1px;' }, title),
            E('div', { 'style': 'margin-top: 10px; max-height: 150px; overflow-y: auto; padding-right: 5px;' }, listItems)
        ]);
    },

    render: function() {
        var self = this;
        
        var searchInput = E('input', {
            'type': 'text',
            'id': 'firewall-search-input',
            'placeholder': 'Search Time, Action, Rule, IP, Proto...',
            'class': 'cbi-input-text',
            'style': 'flex: 1; padding: 10px 15px; background: #1e1e1e; color: #fff; border: 1px solid #333; border-radius: 6px; box-shadow: inset 0 2px 4px rgba(0,0,0,0.2); outline: none; min-width: 200px;'
        });

        // Reset page back to 0 whenever user searches
        searchInput.addEventListener('input', function() {
            self.currentPage = 0;
        });

        // Top Left Pagination Controls
        var prevPageBtn = E('button', {
            'class': 'cbi-button',
            'style': 'background: #334155; color: #fff; border: 1px solid #475569; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: background 0.2s;'
        }, '◀');

        var nextPageBtn = E('button', {
            'class': 'cbi-button',
            'style': 'background: #334155; color: #fff; border: 1px solid #475569; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: background 0.2s;'
        }, '▶');

        var pageIndicator = E('span', {
            'style': 'color: #38bdf8; font-weight: 600; font-size: 13px; font-family: monospace; white-space: nowrap;'
        }, '1 - 100');

        var paginationWrapper = E('div', {
            'style': 'display: flex; align-items: center; gap: 8px; background: #18181b; padding: 4px 10px; border-radius: 6px; border: 1px solid #27272a;'
        }, [ prevPageBtn, pageIndicator, nextPageBtn ]);

        prevPageBtn.addEventListener('click', function() {
            if (self.currentPage > 0) {
                self.currentPage--;
            }
        });

        nextPageBtn.addEventListener('click', function() {
            var maxPage = Math.floor((self.currentFilteredItems.length - 1) / self.pageSize);
            if (self.currentPage < maxPage) {
                self.currentPage++;
            }
        });

        var pauseBtn = E('button', {
            'class': 'cbi-button',
            'style': 'background: #0ea5e9; color: #fff; border: none; padding: 10px 15px; border-radius: 6px; cursor: pointer; font-weight: 600; min-width: 130px; transition: background 0.3s;'
        }, '⏸ Pause Logs');

        var exportBtn = E('button', {
            'class': 'cbi-button',
            'style': 'background: #8b5cf6; color: #fff; border: none; padding: 10px 15px; border-radius: 6px; cursor: pointer; font-weight: 600; transition: background 0.3s;'
        }, '💾 Export CSV');

        var clearBtn = E('button', {
            'class': 'cbi-button',
            'style': 'background: #ef4444; color: #fff; border: none; padding: 10px 15px; border-radius: 6px; cursor: pointer; font-weight: 600; transition: background 0.3s;'
        }, '🗑 Clear Logs');

        pauseBtn.addEventListener('click', function() {
            self.isPaused = !self.isPaused;
            this.textContent = self.isPaused ? '▶ Resume Logs' : '⏸ Pause Logs';
            this.style.background = self.isPaused ? '#10b981' : '#0ea5e9'; 
        });

        exportBtn.addEventListener('click', function() {
            var csv = 'Time,Action,Rule,Interface,MAC,Source,Destination,Protocol\n';
            self.currentFilteredItems.forEach(function(i) {
                csv += [i.timeString, i.action, i.rule, i.inFace, i.macStr, (i.src+i.spt), (i.dst+i.dpt), i.proto].join(',') + '\n';
            });
            var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'firewall_logs.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        });

        clearBtn.addEventListener('click', function() {
            self.clear_ts = Date.now(); 
            self.currentPage = 0;
        });

        var searchWrapper = E('div', { 'style': 'display: flex; width: 100%; margin-bottom: 5px; gap: 10px; flex-wrap: wrap; align-items: center;' }, [ paginationWrapper, searchInput, pauseBtn, exportBtn, clearBtn ]);
        var searchHint = E('div', { 'style': 'font-size: 11px; color: #a1a1aa; margin-bottom: 15px; margin-left: 5px; font-style: italic;' }, 
            '💡 Guide: Search by IP (192.168.1.1), Action (DROP), or a Time Range (e.g., 20:00:00 - 21:00:00)'
        );

        var statContainer = E('div', { 'style': 'display: flex; flex-wrap: wrap; margin-bottom: 20px; margin-left: -10px; margin-right: -10px;' }, []);
        var tableBody = E('tbody', { 'id': 'firewall-log-rows' });

        var headerBanner = E('div', { 
            'style': 'margin-bottom: 25px; padding: 20px 25px; background: linear-gradient(145deg, #18181b 0%, #09090b 100%); border-left: 6px solid #0ea5e9; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: space-between;' 
        }, [
            E('div', {}, [
                E('h1', { 'style': 'margin: 0; font-size: 32px; font-weight: 900; letter-spacing: 3px; text-transform: uppercase; background: linear-gradient(90deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; filter: drop-shadow(0px 2px 4px rgba(0,0,0,0.5));' }, 'GOT JOED'),
                E('div', { 'style': 'color: #a1a1aa; font-size: 14px; margin-top: 6px; font-weight: 600; letter-spacing: 1px; text-transform: uppercase;' }, 'Live Firewall Monitoring ⚡')
            ]),
            E('div', { 'style': 'background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); color: #10b981; padding: 6px 12px; border-radius: 20px; font-size: 11px; font-weight: bold; letter-spacing: 1px; display: flex; align-items: center; gap: 8px;' }, [
                E('span', { 'style': 'display: inline-block; width: 8px; height: 8px; background: #10b981; border-radius: 50%; box-shadow: 0 0 8px #10b981;' }, ''),
                'SYSTEM ACTIVE'
            ])
        ]);

        var container = E('div', { 'class': 'cbi-map', 'style': 'padding: 10px;' }, [
            headerBanner,
            searchWrapper, 
            searchHint,    
            statContainer,
            E('div', { 'style': 'background: #1e1e1e; border: 1px solid #333; border-radius: 8px; overflow-x: auto; box-shadow: 0 4px 6px rgba(0,0,0,0.3);' }, [
                E('table', { 'class': 'table', 'style': 'width: 100%; min-width: 850px; font-size: 13px; margin: 0; border: none; white-space: nowrap;' }, [
                    E('thead', { 'style': 'background: #27272a;' }, [
                        E('tr', { 'class': 'tr table-titles', 'style': 'color: #a1a1aa; text-align: left;' }, [
                            E('th', { 'class': 'th', 'style': 'padding: 12px;' }, 'Time'),
                            E('th', { 'class': 'th', 'style': 'padding: 12px;' }, 'Action'),
                            E('th', { 'class': 'th', 'style': 'padding: 12px;' }, 'Rule Match'),
                            E('th', { 'class': 'th', 'style': 'padding: 12px;' }, 'Interface'),
                            E('th', { 'class': 'th', 'style': 'padding: 12px;' }, 'Source'),
                            E('th', { 'class': 'th', 'style': 'padding: 12px;' }, 'Destination'),
                            E('th', { 'class': 'th', 'style': 'padding: 12px;' }, 'Proto')
                        ])
                    ]),
                    tableBody
                ])
            ])
        ]);

        poll.add(function() {
            if (self.isPaused) return Promise.resolve();

            return fs.exec('sh', ['-c', 'cat /proc/uptime | cut -d" " -f1 && dmesg | tail -n 10000']).then(function(res) {
                if (!res || !res.stdout) return;
                
                var lines = res.stdout.trim().split('\n');
                var uptimeSeconds = parseFloat(lines.shift()); 
                var bootTimeMs = Date.now() - (uptimeSeconds * 1000); 

                var allItems = []; 
                var dynStats = { src: {}, dst: {}, rule: {}, port: {} };

                for (var i = lines.length - 1; i >= 0; i--) {
                    if (!lines[i]) continue;
                    var parsed = self.parseLogLine(lines[i]);
                    if (!parsed) continue;

                    if (parsed.src.indexOf(':') !== -1 || parsed.dst.indexOf(':') !== -1) continue;
                    
                    var logTimeMs = bootTimeMs + (parsed.ts * 1000);
                    if (logTimeMs < self.clear_ts) break; 
                    
                    parsed.timeString = new Date(logTimeMs).toLocaleTimeString('en-GB'); 

                    // Extract complete MAC address from packet string
                    var macStr = '';
                    if (parsed.macOrig) {
                        var srcPart = parsed.macOrig.substring(18, 35);
                        if (srcPart.match(/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/)) {
                            macStr = srcPart;
                        } else {
                            macStr = parsed.macOrig;
                        }
                    }
                    parsed.macStr = macStr;

                    allItems.push(parsed);
                }

                var searchQuery = searchInput.value.toLowerCase().trim();
                var filteredItems = allItems;

                if (searchQuery) {
                    var timeRangeMatch = searchQuery.match(/(\d{1,2}:\d{2}(?::\d{2})?)\s*-\s*(\d{1,2}:\d{2}(?::\d{2})?)/);
                    
                    if (timeRangeMatch) {
                        var startT = timeRangeMatch[1];
                        var endT = timeRangeMatch[2];
                        
                        if (startT.length <= 5) startT += ':00';
                        if (endT.length <= 5) endT += ':59';
                        if (startT.length === 7) startT = '0' + startT;
                        if (endT.length === 7) endT = '0' + endT;

                        filteredItems = allItems.filter(function(item) {
                            var itemT = item.timeString;
                            if (itemT.length === 7) itemT = '0' + itemT; 
                            return itemT >= startT && itemT <= endT;
                        });
                        
                        // Apply additional term filters if the user combined a time range with text
                        var remainingQuery = searchQuery.replace(timeRangeMatch[0], '').trim();
                        if (remainingQuery) {
                            var tokens = remainingQuery.split(/\s+/);
                            filteredItems = filteredItems.filter(function(item) {
                                var searchStr = [
                                    item.timeString, item.action, item.rule, item.inFace, 
                                    item.src + item.spt, item.dst + item.dpt, item.proto, item.macStr
                                ].join(' ').toLowerCase();
                                return tokens.every(function(token) {
                                    return searchStr.indexOf(token) !== -1;
                                });
                            });
                        }
                    } else {
                        var tokens = searchQuery.split(/\s+/);
                        filteredItems = allItems.filter(function(item) {
                            var searchStr = [
                                item.timeString, item.action, item.rule, item.inFace, 
                                item.src + item.spt, item.dst + item.dpt, item.proto, item.macStr
                            ].join(' ').toLowerCase();
                            
                            // Check that EVERY search token exists in the row string (Narrowing Down)
                            return tokens.every(function(token) {
                                return searchStr.indexOf(token) !== -1;
                            });
                        });
                    }
                }

                self.currentFilteredItems = filteredItems;

                filteredItems.forEach(function(item) {
                    if (item.src !== '-') dynStats.src[item.src] = (dynStats.src[item.src] || 0) + 1;
                    if (item.dst !== '-') dynStats.dst[item.dst] = (dynStats.dst[item.dst] || 0) + 1;
                    dynStats.rule[item.rule] = (dynStats.rule[item.rule] || 0) + 1;
                    
                    var pt = item.dpt || item.spt || '-';
                    if (pt !== '-') dynStats.port[pt] = (dynStats.port[pt] || 0) + 1;
                });

                var total = filteredItems.length;
                var startIdx = self.currentPage * self.pageSize;
                
                // Keep page index within valid range
                if (startIdx >= total && total > 0) {
                    self.currentPage = Math.floor((total - 1) / self.pageSize);
                    startIdx = self.currentPage * self.pageSize;
                }

                var endIdx = Math.min(startIdx + self.pageSize, total);
                var displayItems = filteredItems.slice(startIdx, endIdx);

                // Update Pagination Controls UI
                if (total === 0) {
                    pageIndicator.textContent = '0 - 0';
                    prevPageBtn.disabled = true;
                    nextPageBtn.disabled = true;
                } else {
                    pageIndicator.textContent = (startIdx + 1) + ' - ' + endIdx + ' of ' + total;
                    prevPageBtn.disabled = (self.currentPage === 0);
                    nextPageBtn.disabled = (endIdx >= total);
                }

                prevPageBtn.style.opacity = prevPageBtn.disabled ? '0.4' : '1';
                nextPageBtn.style.opacity = nextPageBtn.disabled ? '0.4' : '1';

                while (statContainer.firstChild) statContainer.removeChild(statContainer.firstChild);
                statContainer.appendChild(self.generateTopList(dynStats.rule, 'Top Rules Hit', searchInput));
                statContainer.appendChild(self.generateTopList(dynStats.src, 'Top Source IPs', searchInput));
                statContainer.appendChild(self.generateTopList(dynStats.dst, 'Top Target IPs', searchInput));
                statContainer.appendChild(self.generateTopList(dynStats.port, 'Top Ports Hit', searchInput));

                while (tableBody.firstChild) tableBody.removeChild(tableBody.firstChild);
                
                if (displayItems.length === 0) {
                     tableBody.appendChild(E('tr', {}, [
                         E('td', { 'colspan': '7', 'style': 'text-align: center; padding: 20px; color: #a1a1aa; font-style: italic;' }, 'No matching logs found in history.')
                     ]));
                }
                
                var formatIPHook = function(ipStr) {
                    if (ipStr === '-' || ipStr.indexOf(':') > -1 && ipStr.split(':').length > 2) return ipStr;
                    return E('a', { 
                        'href': 'https://ipinfo.io/' + ipStr, 
                        'target': '_blank', 
                        'style': 'color: inherit; text-decoration: none; border-bottom: 1px dashed currentcolor;',
                        'onclick': 'event.stopPropagation()' 
                    }, ipStr);
                };

                displayItems.forEach(function(item) {
                    var badgeColor = '#52525b'; 
                    if (item.action === 'ALLOW') badgeColor = '#059669'; 
                    if (item.action === 'DROP') badgeColor = '#dc2626'; 
                    if (item.action === 'REJECT') badgeColor = '#d97706'; 

                    var actionBadge = E('span', { 'style': 'background:' + badgeColor + '; color:#fff; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 10px; letter-spacing: 0.5px;' }, item.action);

                    var srcCell = E('div', {}, [
                        formatIPHook(item.src),
                        E('span', {}, item.spt),
                        item.macStr ? E('div', { 'style': 'font-size: 10px; color: #71717a; margin-top: 2px;' }, 'MAC: ' + item.macStr) : ''
                    ]);

                    var dstCell = E('div', {}, [
                        formatIPHook(item.dst),
                        E('span', {}, item.dpt)
                    ]);

                    var tr = E('tr', { 'class': 'tr', 'style': 'border-bottom: 1px solid #27272a; transition: background 0.2s; cursor: pointer;' }, [
                        E('td', { 'class': 'td', 'style': 'color: #71717a; padding: 10px 12px;' }, item.timeString),
                        E('td', { 'class': 'td', 'style': 'padding: 10px 12px;', 'data-search': item.action }, actionBadge),
                        E('td', { 'class': 'td', 'style': 'font-weight: 500; color: #e4e4e7; padding: 10px 12px;' }, item.rule),
                        E('td', { 'class': 'td', 'style': 'color: #a1a1aa; padding: 10px 12px;' }, item.inFace),
                        E('td', { 'class': 'td', 'style': 'font-family: monospace; color: #38bdf8; padding: 10px 12px;' }, srcCell),
                        E('td', { 'class': 'td', 'style': 'font-family: monospace; color: #c084fc; padding: 10px 12px;' }, dstCell),
                        E('td', { 'class': 'td', 'style': 'color: #a1a1aa; padding: 10px 12px;' }, item.proto)
                    ]);
                    
                    tr.addEventListener('mouseenter', function() { this.style.background = '#27272a'; });
                    tr.addEventListener('mouseleave', function() { this.style.background = 'transparent'; });
                    
                    Array.from(tr.childNodes).forEach(function(td) {
                        td.addEventListener('click', function(e) {
                            if (e.target.tagName === 'A') return; 
                            var textToSearch = td.getAttribute('data-search') || td.textContent.trim();
                            if (textToSearch.indexOf('MAC:') > -1) textToSearch = item.src; 
                            
                            var currentTokens = searchInput.value.trim().toLowerCase().split(/\s+/);
                            var newTokens = textToSearch.toLowerCase().split(/\s+/);
                            
                            var alreadyHasTerm = newTokens.every(function(t) { return currentTokens.indexOf(t) !== -1; });
                            
                            if (!alreadyHasTerm || searchInput.value.trim() === '') {
                                searchInput.value = (searchInput.value.trim() + ' ' + textToSearch).trim();
                            }
                            searchInput.dispatchEvent(new Event('input')); 
                        });
                    });

                    tableBody.appendChild(tr);
                });
            });
        }, 2); 

        return container;
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
EOF
```
#### 5. Apply Changes 
```bash
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache/
/etc/init.d/rpcd restart
/etc/init.d/uhttpd restart
```
Then refresh your OpenWrt. 
The Dashboard should now apear at your mother Tabs.

## Screenshots
<img width="1307" height="935" alt="image" src="https://github.com/user-attachments/assets/249e6762-9b47-424b-a8db-a5f59daafccd" />
<img width="1281" height="909" alt="image" src="https://github.com/user-attachments/assets/af41a733-3454-46a0-a63f-9288a2d4ca2e" />


#### To REMOVE everything
```bash
rm -rf /www/luci-static/resources/view/dashboard
rm -f /usr/share/luci/menu.d/luci-app-joeddashboard.json
rm -f /usr/share/rpcd/acl.d/luci-app-joeddashboard.json
rm -f /www/luci-static/resources/view/dashboard/index.js
```
