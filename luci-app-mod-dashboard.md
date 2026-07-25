# luci-app-mod-dashboard

![Version](https://img.shields.io/badge/version-1.0.0-purple.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![OpenWrt](https://img.shields.io/badge/OpenWrt-21.02+-orange.svg)

A fresh installation of OpenWrt 25.x does not come with a built-in visual firewall intelligence dashboard out of the box. This lightweight package bridges that gap by adding a real-time tracking interface directly into your LuCI web UI—letting you visualize dropped and allowed packets, identify top offending IPs, and monitor triggered firewall rules straight from your router without heavy backend databases.

## Features

🛡️ **Live Packet Tracking**
* Real-time monitoring of OpenWrt `dmesg` logs
* Visual badges for firewall actions (ALLOW, DROP, REJECT)
* Protocol identification (TCP, UDP, ICMP)

📊 **Smart Analytics**
* Top Source IPs leaderboard
* Top Target IPs leaderboard
* Top Triggered Firewall Rules tracking

⚡ **Interactive Interface**
* Clickable IP addresses for instant search filtering
* Global search bar

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
'require view';
'require fs';
'require poll';

return view.extend({
    // Store live counters and history for the leaderboards
    last_ts: 0,
    isPaused: false, // --- NEW FEATURE: Pause state for stopping the log feed ---
    stats: {
        src: {},
        dst: {},
        rule: {}
    },
    
    // Generalized parser to extract all key details from dmesg
    parseLogLine: function(line) {
        // Extracts: [ 8433.701] Rule-Name: Payload...
        var match = line.match(/^\[\s*([\d\.]+)\]\s+(.*?):\s+(.*)$/);
        if (!match) return null;

        var ts = parseFloat(match[1]);
        var rule = match[2].trim();
        var payload = match[3];

        // Dynamically extract SRC=, DST=, IN=, etc.
        var kv = {};
        payload.replace(/([A-Z]+)=([^\s]+)/g, function(m, key, val) {
            kv[key] = val;
        });

        // Deduce Action based on rule name keywords
        var action = 'DROP';
        var rLower = rule.toLowerCase();
        if (rLower.indexOf('allow') > -1 || rLower.indexOf('accept') > -1 || rLower.indexOf('pass') > -1) action = 'ALLOW';
        else if (rLower.indexOf('reject') > -1) action = 'REJECT';

        // --- NEW FEATURE: Dynamic Protocol Mapping & Port Identification ---
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
            proto = 'PROTO-' + proto; // Custom/unknown numeric protocols dynamically handled
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
            dpt: fmtPort(kv.DPT)
        };
    },

    // Helper to generate a sorted leaderboard card
    generateTopList: function(statObj, title, searchInput) {
        var sorted = Object.keys(statObj).sort(function(a, b) {
            return statObj[b] - statObj[a];
        }).slice(0, 5); // Get top 5

        var listItems = sorted.map(function(key) {
            var row = E('div', { 'style': 'display: flex; justify-content: space-between; margin-bottom: 8px; border-bottom: 1px solid #333; padding-bottom: 5px; cursor: pointer; transition: background 0.2s;' }, [
                E('span', { 'style': 'font-family: monospace; font-size: 13px; color: #ddd;' }, key),
                E('strong', { 'style': 'color: #38bdf8; background: #0f172a; padding: 2px 8px; border-radius: 12px; font-size: 12px;' }, statObj[key])
            ]);

            // --- NEW FEATURE: Clickable Leaderboard Items to Filter Logs ---
            row.addEventListener('mouseenter', function() { this.style.background = '#27272a'; });
            row.addEventListener('mouseleave', function() { this.style.background = 'transparent'; });
            
            row.addEventListener('click', function() {
                if (searchInput) {
                    searchInput.value = key;
                    // Trigger an input event so the UI updates and the next poll cycle filters the history
                    searchInput.dispatchEvent(new Event('input')); 
                }
            });

            return row;
        });

        if (listItems.length === 0) {
            listItems = [ E('div', { 'style': 'color: #666; font-style: italic; font-size: 13px; text-align: center; padding: 10px 0;' }, 'Awaiting traffic data...') ];
        }

        return E('div', { 'style': 'flex: 1; min-width: 250px; background: #1e1e1e; border: 1px solid #333; border-radius: 8px; padding: 15px; margin: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.3);' }, [
            E('h4', { 'style': 'margin-top: 0; color: #f8fafc; border-bottom: 2px solid #38bdf8; padding-bottom: 8px; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 1px;' }, title),
            E('div', { 'style': 'margin-top: 15px;' }, listItems)
        ]);
    },

    render: function() {
        var self = this;
        
        // --- NEW FEATURE: Search Bar Element ---
        var searchInput = E('input', {
            'type': 'text',
            'id': 'firewall-search-input',
            'placeholder': 'Search Time, Action, Rule, IP, Proto...',
            'class': 'cbi-input-text',
            'style': 'flex: 1; padding: 10px 15px; background: #1e1e1e; color: #fff; border: 1px solid #333; border-radius: 6px; box-shadow: inset 0 2px 4px rgba(0,0,0,0.2); outline: none;'
        });

        // --- RECOMMENDED FEATURE: Pause/Resume Button ---
        var pauseBtn = E('button', {
            'class': 'cbi-button',
            'style': 'margin-left: 15px; background: #0ea5e9; color: #fff; border: none; padding: 10px 15px; border-radius: 6px; cursor: pointer; font-weight: 600; min-width: 130px; transition: background 0.3s;'
        }, '⏸ Pause Logs');

        pauseBtn.addEventListener('click', function() {
            self.isPaused = !self.isPaused;
            this.textContent = self.isPaused ? '▶ Resume Logs' : '⏸ Pause Logs';
            this.style.background = self.isPaused ? '#10b981' : '#0ea5e9'; // Switches to green when paused
        });

        var searchContainer = E('div', { 'style': 'display: flex; width: 100%; margin-bottom: 15px;' }, [ searchInput, pauseBtn ]);

        var statContainer = E('div', { 'style': 'display: flex; flex-wrap: wrap; margin-bottom: 20px; margin-left: -10px; margin-right: -10px;' }, []);
        var tableBody = E('tbody', { 'id': 'firewall-log-rows' });

        // --- NEW FEATURE: Upgraded Ultra-Modern GOT JOED Banner ---
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
            searchContainer, // Append Flex Container with Search & Pause
            statContainer,
            E('div', { 'style': 'background: #1e1e1e; border: 1px solid #333; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.3);' }, [
                E('table', { 'class': 'table', 'style': 'width: 100%; font-size: 13px; margin: 0; border: none;' }, [
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
            // --- NEW FEATURE: Abort polling check if logs are paused ---
            if (self.isPaused) return Promise.resolve();

            // --- NEW FEATURE: Fetch Uptime alongside dmesg (Increased buffer to 1000 lines for deeper search) ---
            return fs.exec('sh', ['-c', 'cat /proc/uptime | cut -d" " -f1 && dmesg | tail -n 1000']).then(function(res) {
                if (!res || !res.stdout) return;
                
                var lines = res.stdout.trim().split('\n');

                // --- NEW FEATURE: Time Calculation Math ---
                var uptimeSeconds = parseFloat(lines.shift()); // Extract Uptime from line 1
                var bootTimeMs = Date.now() - (uptimeSeconds * 1000); // Browser time minus uptime

                var currentBatchTs = 0;
                var tableItems = [];

                // Parse from bottom (newest) to top
                for (var i = lines.length - 1; i >= 0; i--) {
                    if (!lines[i]) continue;
                    var parsed = self.parseLogLine(lines[i]);
                    if (!parsed) continue;

                    // --- NEW FEATURE: Filter out IPv6 Logs ---
                    if (parsed.src.indexOf(':') !== -1 || parsed.dst.indexOf(':') !== -1) continue;

                    // Stats only count NEW events based on timestamp
                    if (parsed.ts > self.last_ts) {
                        if (parsed.src !== '-') self.stats.src[parsed.src] = (self.stats.src[parsed.src] || 0) + 1;
                        if (parsed.dst !== '-') self.stats.dst[parsed.dst] = (self.stats.dst[parsed.dst] || 0) + 1;
                        self.stats.rule[parsed.rule] = (self.stats.rule[parsed.rule] || 0) + 1;
                        
                        if (parsed.ts > currentBatchTs) currentBatchTs = parsed.ts;
                    }
                    
                    // --- NEW FEATURE: Convert to 24H Real-Time ---
                    var logTimeMs = bootTimeMs + (parsed.ts * 1000);
                    parsed.timeString = new Date(logTimeMs).toLocaleTimeString('en-GB'); // en-GB forces 24H format natively

                    if (tableItems.length < 30) tableItems.push(parsed);
                }

                if (currentBatchTs > self.last_ts) self.last_ts = currentBatchTs;

                // --- NEW FEATURE: Apply Search Filter ---
                var searchQuery = searchInput.value.toLowerCase().trim();
                var filteredItems = tableItems;

                if (searchQuery) {
                    filteredItems = tableItems.filter(function(item) {
                        var searchStr = [
                            item.timeString,
                            item.action,
                            item.rule,
                            item.inFace,
                            item.src + item.spt,
                            item.dst + item.dpt,
                            item.proto
                        ].join(' ').toLowerCase();
                        
                        return searchStr.indexOf(searchQuery) !== -1;
                    });
                }

                // 1. Rebuild Stat Cards
                while (statContainer.firstChild) statContainer.removeChild(statContainer.firstChild);
                statContainer.appendChild(self.generateTopList(self.stats.rule, 'Top Rules Hit', searchInput));
                statContainer.appendChild(self.generateTopList(self.stats.src, 'Top Source IPs', searchInput));
                statContainer.appendChild(self.generateTopList(self.stats.dst, 'Top Target IPs', searchInput));

                // 2. Rebuild Table Rows
                while (tableBody.firstChild) tableBody.removeChild(tableBody.firstChild);
                
                if (filteredItems.length === 0) {
                     tableBody.appendChild(E('tr', {}, [
                         E('td', { 'colspan': '7', 'style': 'text-align: center; padding: 20px; color: #a1a1aa; font-style: italic;' }, 'No matching logs found.')
                     ]));
                }
                
                filteredItems.forEach(function(item) {

                    var badgeColor = '#52525b'; // default gray
                    if (item.action === 'ALLOW') badgeColor = '#059669'; // emerald
                    if (item.action === 'DROP') badgeColor = '#dc2626'; // red
                    if (item.action === 'REJECT') badgeColor = '#d97706'; // amber

                    var actionBadge = E('span', { 'style': 'background:' + badgeColor + '; color:#fff; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 10px; letter-spacing: 0.5px;' }, item.action);

                    var tr = E('tr', { 'class': 'tr', 'style': 'border-bottom: 1px solid #27272a; transition: background 0.2s; cursor: pointer;' }, [
                        E('td', { 'class': 'td', 'style': 'color: #71717a; padding: 10px 12px;' }, item.timeString),
                        E('td', { 'class': 'td', 'style': 'padding: 10px 12px;', 'data-search': item.action }, actionBadge),
                        E('td', { 'class': 'td', 'style': 'font-weight: 500; color: #e4e4e7; padding: 10px 12px;' }, item.rule),
                        E('td', { 'class': 'td', 'style': 'color: #a1a1aa; padding: 10px 12px;' }, item.inFace),
                        E('td', { 'class': 'td', 'style': 'font-family: monospace; color: #38bdf8; padding: 10px 12px;' }, item.src + item.spt),
                        E('td', { 'class': 'td', 'style': 'font-family: monospace; color: #c084fc; padding: 10px 12px;' }, item.dst + item.dpt),
                        E('td', { 'class': 'td', 'style': 'color: #a1a1aa; padding: 10px 12px;' }, item.proto)
                    ]);
                    
                    // Hover effect
                    tr.addEventListener('mouseenter', function() { this.style.background = '#27272a'; });
                    tr.addEventListener('mouseleave', function() { this.style.background = 'transparent'; });
                    
                    // --- NEW FEATURE: Clickable Cells to Search ---
                    Array.from(tr.childNodes).forEach(function(td) {
                        td.addEventListener('click', function() {
                            // Extract text, handling cases like the action badge which has inner spans
                            var textToSearch = td.getAttribute('data-search') || td.textContent.trim();
                            // Optional: Strip port info if clicking an IP so it searches the whole IP
                            // if (textToSearch.indexOf(':') > 0 && (td.style.color === 'rgb(56, 189, 248)' || td.style.color === 'rgb(192, 132, 252)')) {
                            //    textToSearch = textToSearch.split(':')[0];
                            // }
                            searchInput.value = textToSearch;
                            // Trigger an input event so any listeners (if we added real-time filtering) would fire
                            searchInput.dispatchEvent(new Event('input')); 
                        });
                    });

                    tableBody.appendChild(tr);
                });
            });
        }, 2); // Poll every 2 seconds

        return container;
    },

    // Remove the default LuCI Save/Apply buttons
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
<img width="1342" height="913" alt="dashboard" src="https://github.com/user-attachments/assets/48224aff-21bc-4e57-af0a-4fe1b1bad7b4" />

#### To REMOVE everything
```bash
rm -rf /www/luci-static/resources/view/dashboard
rm -f /usr/share/luci/menu.d/luci-app-joeddashboard.json
rm -f /usr/share/rpcd/acl.d/luci-app-joeddashboard.json
rm -f /www/luci-static/resources/view/dashboard/index.js
```
