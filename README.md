# suritui

A read-only terminal viewer for Suricata alerts. It shows the alerts of a
Suricata sensor (for example on a router) in a sidebar-and-list screen with
vi-style keys: alerts grouped by Emerging Threats category, a key to hide
informational ones, the last 14 days, a detail view, the full rule text, and
the raw JSON.

## Read-only guarantee

suritui never writes to the router and never changes Suricata, its
configuration or its rules. The viewer reads alert lines over ssh and makes no
other network call. The one exception is the separate command
`suritui update-rules`, which downloads the public Emerging Threats Open rules
tarball to your own machine (see below). There is no key that disables a rule,
reloads Suricata or blocks anything.

## How it works

suritui runs `ssh` (with a fixed argument list, never through a shell) and
asks the router for one of exactly two things:

- `live`: today's alerts
- `day K`: the alerts of a rotated log, K = 0 to 13 (0 is yesterday)

A small forced-command script on the router must answer those two commands.
The contract: print the `alert`-type events of today's `eve.json` (for `live`)
or of the rotated `eve.json.K.gz` (for `day K`) as raw JSON lines, and nothing
else; exit 2 for any other command and 3 when the requested day does not exist.

Create a dedicated account on the router for this, with a locked password, no
sudo, and read access to the Suricata log only (for example through a dedicated
group). Then restrict
its key to the script in `authorized_keys`:

```
restrict,from="<hub>",command="/path/to/alerts-script" ssh-ed25519 AAAA... suritui
```

`<hub>` is the machine that runs suritui. A minimal script (POSIX sh) that
satisfies the contract:

```sh
#!/bin/sh
# Forced command: prints alert events as raw JSON lines, nothing else.
LOG=/var/log/suricata/eve.json
set -f
set -- $SSH_ORIGINAL_COMMAND

alerts() { grep -F '"event_type":"alert"'; }

case "$#" in
1)
    [ "$1" = live ] || exit 2
    [ -r "$LOG" ] || exit 3
    alerts < "$LOG"
    ;;
2)
    [ "$1" = day ] || exit 2
    case "$2" in
        [0-9] | 1[0-3]) ;;
        *) exit 2 ;;
    esac
    [ -r "$LOG.$2.gz" ] || exit 3
    gzip -dc "$LOG.$2.gz" | alerts
    ;;
*)
    exit 2
    ;;
esac
exit 0
```

It matches the compact JSON that Suricata writes by default
(`"event_type":"alert"` without spaces). Adjust the log path and the rotation
naming to your system.

## Build

```
cargo build --release
```

The binary is `target/release/suritui`. It needs a Rust toolchain and the
`ssh` command at run time.

## Configuration

suritui reads `~/.config/suritui/config.toml`:

```toml
# required (or pass --router)
router = "<router-address>"

# optional
user = "alertview"                  # ssh user on the router (default: alertview)
rules_dir = "/path/to/rules"        # local copy of the ET rules
                                    # (default: ~/.local/share/suritui/rules)
et_version = "8.0.0"                # ET Open path used by update-rules (default: 8.0.0)

# optional: show a label instead of the raw interface name
[labels]
eth0 = "WAN"
```

Flags override the file:

| Flag | Meaning |
|------|---------|
| `--config <PATH>` | use this config file |
| `--router <HOST>` | router to read alerts from |
| `--user <NAME>` | ssh user on the router |
| `--rules-dir <DIR>` | directory with the local copy of the rules |

The flags also work after `update-rules`. Without a router address the viewer
exits with a message; `update-rules` does not need one.

## Updating the rules

```
suritui update-rules
```

Downloads `https://rules.emergingthreats.net/open/suricata-<et_version>/emerging.rules.tar.gz`,
unpacks the `.rules` files into the rules directory
(`~/.local/share/suritui/rules` by default) and replaces the previous copy. It
is the only command that uses the network besides the ssh reads, and it
downloads over HTTPS only. The viewer never downloads anything itself. To keep
the copy fresh, run it from cron:

```
17 4 * * * /path/to/suritui update-rules >/dev/null
```

The `>/dev/null` drops the normal output; errors still go to stderr, so cron
only sends mail when the update fails.

## Screens and keys

Start `suritui`. Today's alerts load first; other days load when you move to
them.

**List** (the main screen). The sidebar lists categories with the alert count
of the current day. First `All`, then the ET categories by count (highest
first, ties alphabetical), then `SURICATA (decoder)` and `Other` last. The ET
category is the word after `ET ` in the signature (`ET DNS Query ...` goes to
`DNS`); signatures starting with `SURICATA ` go to `SURICATA (decoder)`; the
rest go to `Other`. Only categories that have alerts are listed. The list shows
newest first: time, interface, source, destination, signature. The `action` is
shown (in red) only when it is not `allowed`, so alerts a Suricata IPS blocked
stand out. Critical and Major alerts are bold yellow; informational ones are
dim. A status line at the bottom always shows what is shown and what is hidden; the
last error, if any, is appended after a `|`. The error clears on the next
action that changes the view or moves the selection, or on a successful reload.

| Key | Action |
|-----|--------|
| `Tab` / `Shift-Tab` | next / previous category |
| `j` `k`, Down Up | move in the list |
| `g` / Home, `G` / End | first / last row |
| PageUp / PageDown | move 20 rows up / down |
| `Enter` | open the alert detail |
| `i` | hide / show informational alerts |
| `[` `]` | older / newer day (Today, Yesterday, back to 14 days ago) |
| `R` | re-read the current day from the router |
| `?` | help |
| `q`, `Ctrl-C` | quit (works on every screen) |

"Informational" means ET `signature_severity` is `Informational`, or, when an
alert has none (decoder events), Suricata severity 3. By default everything is
shown.

**Detail** (`Enter`): signature, time, interface, source, destination,
protocol, action (bold red when it is not `allowed`), SID and rev, severities,
confidence, MITRE technique and tactic, DNS/TLS/HTTP context, Suricata
category (classtype), attack target, affected product, app protocol, and the
rule's created and updated dates; missing fields show `-`.

| Key | Action |
|-----|--------|
| `r` | rule text |
| `w` | raw JSON |
| `Esc` | back to the list |
| `j` `k`, Down Up | scroll one line |
| PageUp / PageDown | scroll about one page |
| `g` / Home, `G` / End | jump to the top / bottom |

The detail and raw JSON screens scroll with the keys above (long lines are
wrapped). When the text does not fit, the bottom line shows the visible range,
for example `lines 5-22 of 41`. The position goes back to the top whenever you
change screen.

**Rule** (`r` from the detail): the full rule looked up by SID in the local
copy of ET Open. Limits you should know: it is the copy on the machine running
suritui, not the router's own rules file; if its `rev` differs from the alert's
a warning says so; and whether the rule is enabled or disabled on the router is
not known (the screen says this). If the SID is not found (a local rule or one
removed upstream) or the rules are not installed, the screen says that. `Esc`
goes back to the list.

**Raw JSON** (`w` from the detail): the alert event, pretty-printed. `Esc` goes
back to the list.

Keys that change what the list shows (categories, days, `i`, `R`, selection)
work only on the list screen. Toggling `i`, changing category or day, or
refreshing returns you to the list.

## Security notes

- ssh runs with `BatchMode=yes` (never prompts) and `StrictHostKeyChecking=yes`
  (an unknown or changed host key is an error, never accepted automatically;
  a changed key is reported as such in the status line).
  The router's host key must already be in `known_hosts`.
- Only the commands `live` and `day K` with K from 0 to 13 are ever sent; a
  larger day is rejected before ssh starts.
- Alert contents are untrusted. Control characters and bidirectional-text
  overrides in alert text, rule text and raw JSON are replaced with `?` before
  they reach the terminal.
- `update-rules` refuses to replace a directory that holds anything other than
  regular `.rules` files, so a wrong `rules_dir` cannot wipe other data. It
  limits the download and the unpacked size, and extracts only `.rules` files
  by name (never by archive path).
- The real download uses HTTPS only.

## Known limitations

- The rule and help screens do not scroll: text longer than the terminal is
  cut off. Only the detail and raw JSON screens scroll.
- Text width is counted in characters, not display cells, so wide (CJK, emoji)
  characters can misalign columns.
- ssh runs with `ConnectTimeout=10`, `ServerAliveInterval=10` and
  `ServerAliveCountMax=3`, so an unreachable or hung router fails after about
  10 to 40 seconds, but the screen is still blocked until then.
- Data is limited to today plus the 14 rotated logs the router script serves;
  there is no combined multi-day view.
- On narrow terminals the signature column shrinks first. The sidebar does not
  scroll: with more categories than rows, the extra ones are cut off.
