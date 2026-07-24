# OpenWrt Live Firewall Intelligence Dashboard

![Version](https://img.shields.io/badge/version-1.0.0-purple.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![OpenWrt](https://img.shields.io/badge/OpenWrt-21.02+-orange.svg)

A real-time firewall intelligence dashboard for OpenWrt LuCI. Visualize dropped and allowed packets, identify top offending IPs, and monitor triggered firewall rules directly from your router.

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
* LuCI web interface installed
* SSH access to your router

#### 1. Create Directory Structure
```bash
mkdir -p /www/luci-static/resources/view/dashboard
```

#### 2. Register LuCi Menu
```bash
vi /usr/share/luci/menu.d/luci-app-mod-dashboard.json
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
                }
        }
}
```
#### 3. Setup ACL Permissions
```bash
vi /usr/share/rpcd/acl.d/luci-app-mod-dashboard.json
```
Paste the following:
```bash
{
        "luci-app-dashboard": {
                "description": "Access to Dashboard",
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
```
#### 4. Add the Frontend Code
```bash
vi /www/luci-static/resources/view/dashboard/index.js
```
Paste the following:
```bash
'require view';
'require fs';
'require poll';

return view.extend({
    // Store live counters and history for the leaderboards
    last_ts: 0,
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

        // Map Protocol numbers to readable names
        var proto = kv.PROTO || '-';
        if (proto === '1') proto = 'ICMP';
        if (proto === '2') proto = 'IGMP';
        if (proto === '6') proto = 'TCP';
        if (proto === '17') proto = 'UDP';

        return {
            ts: ts,
            rule: rule,
            action: action,
            inFace: kv.IN || '-',
            src: kv.SRC || '-',
            dst: kv.DST || '-',
            proto: proto,
            spt: kv.SPT ? ':' + kv.SPT : '',
            dpt: kv.DPT ? ':' + kv.DPT : ''
        };
    },

    // Helper to generate a sorted leaderboard card
    generateTopList: function(statObj, title) {
        var sorted = Object.keys(statObj).sort(function(a, b) {
            return statObj[b] - statObj[a];
        }).slice(0, 5); // Get top 5

        var listItems = sorted.map(function(key) {
            return E('div', { 'style': 'display: flex; justify-content: space-between; margin-bottom: 8px; border-bottom: 1px solid #333; padding-bottom: 5px;' }, [
                E('span', { 'style': 'font-family: monospace; font-size: 13px; color: #ddd;' }, key),
                E('strong', { 'style': 'color: #38bdf8; background: #0f172a; padding: 2px 8px; border-radius: 12px; font-size: 12px;' }, statObj[key])
            ]);
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
            'placeholder': 'Search Time, Action, Rule, IP, Proto...',
            'class': 'cbi-input-text',
            'style': 'width: 100%; padding: 10px 15px; margin-bottom: 15px; background: #1e1e1e; color: #fff; border: 1px solid #333; border-radius: 6px; box-shadow: inset 0 2px 4px rgba(0,0,0,0.2); outline: none;'
        });

        var statContainer = E('div', { 'style': 'display: flex; flex-wrap: wrap; margin-bottom: 20px; margin-left: -10px; margin-right: -10px;' }, []);
        var tableBody = E('tbody', { 'id': 'firewall-log-rows' });

        var container = E('div', { 'class': 'cbi-map', 'style': 'padding: 10px;' }, [
            E('h2', { 'style': 'margin-bottom: 20px; font-weight: 300; color: #fff;' }, 'Live Firewall Intelligence'),
            searchInput, // --- NEW FEATURE: Append Search Bar here ---
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
            // --- NEW FEATURE: Fetch Uptime alongside dmesg to calculate real-world time ---
            return fs.exec('sh', ['-c', 'cat /proc/uptime | cut -d" " -f1 && dmesg | tail -n 150']).then(function(res) {
                if (!res || !res.stdout) return;
                
                var lines = res.stdout.trim().split('\n');
                
                // --- NEW FEATURE: Time Calculation Math ---
                var uptimeSeconds = parseFloat(lines.shift()); // Extract Uptime from line 1
                var bootTimeMs = Date.now() - (uptimeSeconds * 1000); // Browser time minus uptime

                var currentBatchTs = 0;
                var tableItems = [];
                var filterText = searchInput.value.toLowerCase(); // Get current search query

                // Parse from bottom (newest) to top
                for (var i = lines.length - 1; i >= 0; i--) {
                    if (!lines[i]) continue;
                    var parsed = self.parseLogLine(lines[i]);
                    if (!parsed) continue;

                    // --- NEW FEATURE: Filter out IPv6 Logs ---
                    if (parsed.src.indexOf(':') !== -1 || parsed.dst.indexOf(':') !== -1) continue;

                    if (tableItems.length < 30) tableItems.push(parsed);

                    // Stats only count NEW events based on timestamp
                    if (parsed.ts > self.last_ts) {
                        if (parsed.src !== '-') self.stats.src[parsed.src] = (self.stats.src[parsed.src] || 0) + 1;
                        if (parsed.dst !== '-') self.stats.dst[parsed.dst] = (self.stats.dst[parsed.dst] || 0) + 1;
                        self.stats.rule[parsed.rule] = (self.stats.rule[parsed.rule] || 0) + 1;
                        
                        if (parsed.ts > currentBatchTs) currentBatchTs = parsed.ts;
                    }
                }

                if (currentBatchTs > self.last_ts) self.last_ts = currentBatchTs;

                // 1. Rebuild Stat Cards
                while (statContainer.firstChild) statContainer.removeChild(statContainer.firstChild);
                statContainer.appendChild(self.generateTopList(self.stats.rule, 'Top Rules Hit'));
                statContainer.appendChild(self.generateTopList(self.stats.src, 'Top Source IPs'));
                statContainer.appendChild(self.generateTopList(self.stats.dst, 'Top Target IPs'));

                // 2. Rebuild Table Rows
                while (tableBody.firstChild) tableBody.removeChild(tableBody.firstChild);
                
                tableItems.forEach(function(item) {
                    // --- NEW FEATURE: Convert to 24H Real-Time ---
                    var logTimeMs = bootTimeMs + (item.ts * 1000);
                    var timeString = new Date(logTimeMs).toLocaleTimeString('en-GB'); // en-GB forces 24H

                    // --- NEW FEATURE: Search Filter Logic ---
                    var rowString = [timeString, item.action, item.rule, item.inFace, item.src, item.dst, item.proto].join(' ').toLowerCase();
                    if (filterText && rowString.indexOf(filterText) === -1) return; // Skip if no match

                    var badgeColor = '#52525b'; // default gray
                    if (item.action === 'ALLOW') badgeColor = '#059669'; // emerald
                    if (item.action === 'DROP') badgeColor = '#dc2626'; // red
                    if (item.action === 'REJECT') badgeColor = '#d97706'; // amber

                    var actionBadge = E('span', { 'style': 'background:' + badgeColor + '; color:#fff; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 10px; letter-spacing: 0.5px;' }, item.action);

                    // --- NEW FEATURE: Clickable IPs ---
                    var srcSpan = E('span', { 'style': 'cursor: pointer; border-bottom: 1px dashed #38bdf8;', 'title': 'Click to filter' }, item.src + item.spt);
                    var dstSpan = E('span', { 'style': 'cursor: pointer; border-bottom: 1px dashed #c084fc;', 'title': 'Click to filter' }, item.dst + item.dpt);

                    // When clicked, inject the IP into the search bar
                    srcSpan.addEventListener('click', function() { searchInput.value = item.src; });
                    dstSpan.addEventListener('click', function() { searchInput.value = item.dst; });

                    var tr = E('tr', { 'class': 'tr', 'style': 'border-bottom: 1px solid #27272a; transition: background 0.2s;' }, [
                        E('td', { 'class': 'td', 'style': 'color: #71717a; padding: 10px 12px;' }, timeString), // Replaced item.ts with real time
                        E('td', { 'class': 'td', 'style': 'padding: 10px 12px;' }, actionBadge),
                        E('td', { 'class': 'td', 'style': 'font-weight: 500; color: #e4e4e7; padding: 10px 12px;' }, item.rule),
                        E('td', { 'class': 'td', 'style': 'color: #a1a1aa; padding: 10px 12px;' }, item.inFace),
                        E('td', { 'class': 'td', 'style': 'font-family: monospace; color: #38bdf8; padding: 10px 12px;' }, srcSpan), // Replaced with clickable span
                        E('td', { 'class': 'td', 'style': 'font-family: monospace; color: #c084fc; padding: 10px 12px;' }, dstSpan), // Replaced with clickable span
                        E('td', { 'class': 'td', 'style': 'color: #a1a1aa; padding: 10px 12px;' }, item.proto)
                    ]);
                    
                    // Hover effect
                    tr.addEventListener('mouseenter', function() { this.style.background = '#27272a'; });
                    tr.addEventListener('mouseleave', function() { this.style.background = 'transparent'; });
                    
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
```
#### 5. Apply Changes 
```bash
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache/
/etc/init.d/rpcd restart
/etc/init.d/uhttpd restart
```
Then refresh your OpenWrt.












