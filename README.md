# Naxsi Wazuh Integration

The goal of this project is to ship [Naxsi](https://github.com/nbs-system/naxsi) WAF events from my [Custom Naxsi Configs](https://github.com/stylersnico/Custom-Naxsi-Configs) reverse-proxy into Wazuh as real, decoded, alertable events instead of raw text sitting in a log file.

* Custom decoder for Naxsi's `NAXSI_FMT:` log line format
* Rules for blocked/dropped requests, split by attack class (SQLi, XSS, traversal, RFI)
* A correlation rule flagging repeated blocks from the same source IP (scan detection)
* Ready-to-paste agent `<localfile>` block for every vhost on the reverse-proxy

--------

## Structure

```
decoders/
└── local_decoder.xml       # parses NAXSI_FMT lines into srcip/url/action/data fields
rules/
└── local_rules.xml         # block/drop alerts + per-attack-class rules + scan correlation
agent/
└── naxsi_localfile.conf    # <localfile> entries, one per reverse-proxy vhost
```

--------

## Installation

### 1. Agent side (the reverse-proxy)

Paste the contents of `agent/naxsi_localfile.conf` inside the `<ossec_config>` section of `/var/ossec/etc/ossec.conf`, then restart the agent:
```bash
service wazuh-agent restart
```

### 2. Manager side

Paste the contents of `local_decoder.xml` and `rules/local_rules.xml` in `/var/ossec/etc/decoders/local_decoder.xml` and `/var/ossec/etc/rules/local_rules.xml`

> :warning: **Rule IDs 100200-100207 are custom-range placeholders.** If you already have other local rules in that range, renumber before deploying - `wazuh-analysisd` will refuse to start on a collision, same as it refuses on any other config error.

Restart the manager:
```bash
service wazuh-manager restart
```

--------

## Validating before you restart in production

`wazuh-logtest` lets you replay a real log line against the decoder/rules without touching the running service:
```bash
/var/ossec/bin/wazuh-logtest
```

Paste a real `naxsi_error.log` line, e.g.:
```
2026/09/22 09:19:18 [error] 81500#100360: NAXSI_FMT: ip=3.79.134.69&server=files.nicolas-simond.ch&uri=/login&config=block&rid=6b99fb430a933b84bf4b87ab6be55c8e&cscore0=$XSS&score0=32&zone0=HEADERS&id0=1315&var_name0=cookie
```

Expected result: decoder `naxsi` matches, rule `100201` (blocked) fires, then `100204` (XSS) fires as a child rule.

--------

## Checking in Wazuh

In your threat hunting in Wazuh, you will now see all the events: 
<img width="1703" height="1007" alt="image" src="https://github.com/user-attachments/assets/89769789-6203-4175-afd3-a1b3137e9e1c" />


## Known gotchas

* `action` and `extra_data` are **static/reserved field names** in Wazuh - trying to match them with `<field name="action">`/`<field name="extra_data">` fails rule loading with `Field 'X' is static.` and takes the whole manager down. That's why the decoder emits `naxsi_action` / `naxsi_data` instead of the "obvious" names.
* `naxsi_error.log` isn't real RFC3164 syslog (no priority/hostname/program header) - the `syslog` `log_format` on the agent side just means "plain text, line by line"; all the actual field extraction happens in the decoder's `regex`, not from a syslog header.
* One `NAXSI_FMT:` line can carry more than one matched rule (multiple `cscoreN`/`scoreN`/`zoneN`/`idN`/`var_nameN` groups) - the decoder doesn't enumerate them individually since the count varies; they all land in the single `naxsi_data` field, which the attack-class rules regex-match against (`\$SQL`, `\$XSS`, ...).
