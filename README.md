# suritui

A terminal UI for Suricata on a FreeBSD router: look at the alerts, and, if
you want, manage the rules from the same screen. Vi-style keys, a handful of
screens, a confirmation before every change.

It was written for one home router running Suricata 8 as a passive IDS
(`--pcap`) under the unprivileged `suricata` user, and it has only run there
and on one test VM. Read "What it has not been tested on" before you trust it
with a router that matters to you.

**How it was made.** It was written with Claude through Claude Code. The
author directed and tested it but did not write the code by hand.

## Two ways to use it

| | Remote (read-only) | Local (on the router) |
|---|---|---|
| Where it runs | any machine that can ssh to the router | on the router |
| Alerts | yes, over a restricted ssh account | yes, through the helper |
| Rule text | a local copy of ET Open | the rules Suricata really loads |
| Change anything on the router | **never** | yes: disable or enable a rule, silence a source, update rules, switch rule sources, store a source key |
| Needs on the router | one forced-command script (below) | `suritui-admin` plus a sudoers file (below) |

Remote mode keeps the original guarantee: suritui never writes to the router
and never changes Suricata. Local mode can change things, so it is built
differently (next section).

## Local mode: what can change, and how it is kept safe

Local mode is for running `suritui --local` on the router itself. The TUI never
runs as root. Everything that needs root is one small program,
`suritui-admin`, that the TUI starts through `sudo -n`. The sudoers file lists
exactly the helper commands the TUI uses and nothing else
(`suritui print-sudoers ACCOUNT` prints it). The helper accepts a fixed set of
verbs, takes no paths or free text, and checks its own arguments again.

What it can change, and nothing more:

- `disable.conf` / `enable.conf` (disable or enable one rule by SID)
- `threshold.config` (silence a rule for one source or destination)
- the rule set: it runs `suricata-update` and reloads Suricata live (no restart)
- the list of rule sources and, for a source that needs one, its access code

How a change is made:

1. It takes a lock, so two changes never run at once.
2. It builds the new rules in a scratch directory first.
3. It compares them with the live rules. A change is refused unless the only
   differences are the rule you asked for and a few rules that depend on it
   (more than 25 other rules flipping means something is wrong).
4. It keeps a backup, installs the new files, reloads Suricata and waits until
   the reload has really finished.
5. If anything fails, every file goes back and Suricata reloads again.
   Changing a source works the same way: a failed download, check or reload
   puts the whole sources folder back.

Source access codes are read from stdin (never from the command line), kept in
a file only root can read, scrubbed from every output and log line, and never
shown on a confirmation screen. The helper refuses to change sources or store
a code unless `/var/lib/suricata` and `/var/lib/suricata/update` belong to root
(otherwise Suricata's account could swap them); see Install.

It is meant for a **passive IDS** (`suricata --pcap`). It does not manage
drop/reject rules or an inline IPS, and it has not been tried with one.

### Install (local mode, FreeBSD)

You need Rust, `sudo`, Suricata with `suricata-update`, and an ordinary account
that will run suritui. Build, then run the installer from the top of the source
tree:

```
cargo build --release
sudo sh contrib/freebsd/install.sh ACCOUNT
```

The installer checks everything first, keeps the old programs as `*.prev`,
installs `suritui` and `suritui-admin`, generates the sudoers file from the
program you just built, and puts the old sudoers file back if the combined
sudoers files stop parsing. It does not touch Suricata or its files. Read it
before you run it; it is short.

Optional, once, to switch rule sources and store keys from screen 3:

```
chown root:wheel /var/lib/suricata /var/lib/suricata/update
```

Without it everything else works, and the Sources screen explains why it
refuses. Then run `suritui --local` as `ACCOUNT` (or set `local = true` in the
config file).

The helper expects the FreeBSD package layout: `/usr/local/etc/suricata/`
(`disable.conf`, `enable.conf`, `threshold.config`, `suricata.yaml`),
`/var/lib/suricata`, `/var/log/suricata` (`eve.json`, rotated as
`eve.json.N.gz`), `suricata-update` and `suricatasc` in `/usr/local/bin`.
Backups go to `/var/backups/suritui`, the helper's own log to
`/var/log/suritui-admin.log`.

The daily rule update is yours to schedule (for example a root cron job that
runs `suricata-update` and a reload). If that job writes the update output to a
log, make it blank access codes (`oinkcode=`, `secret-code`) first, or a failed
download of a keyed source could put the code in that log.

### Screens in local mode

| Key | Screen |
|-----|--------|
| `1` | alerts (the main screen, below) |
| `2` | rules: `/` search, `s` state filter, `c` clear, `d` / `e` disable / enable the highlighted rule |
| `3` | rule sources: `j` `k` move, `e` switch on (asks for a code if needed), `d` switch off, `R` fetch the current source list |
| `4` | updates: `U` update the rules now |
| `5` | suppress list: `x` removes the highlighted entry |
| `6` | settings (read-only) |
| `7` | logs (`Tab` for the next one) |
| `y` / `Esc` | confirm / cancel a change |

On an alert: `d` disables its rule, `s` / `S` silences the rule for that source
or destination. Every change asks first, then shows progress, then "Done" or
"Failed" with the reason.

## Remote mode: how it works

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

This builds `target/release/suritui` (the TUI) and `target/release/suritui-admin`
(the root helper, local mode only). It needs a Rust toolchain; remote mode also
needs the `ssh` command at run time.

For remote mode only, `cargo install suritui --locked` from crates.io also
works. Do not use it for local mode: the root helper must be installed
root-owned by `contrib/freebsd/install.sh` from a source tree (a clone of this
repository or the unpacked crate), as described below.

## Configuration

suritui reads `~/.config/suritui/config.toml`:

```toml
# required (or pass --router)
router = "<router-address>"

# optional
local = false                       # true: run on the router itself (local mode)
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
| `--local` | run on the router itself (local mode; no router address needed) |

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

## What it has not been tested on

- One router (FreeBSD, Suricata 8.0.7, passive `--pcap`, ET Open) and one
  FreeBSD test VM. Other FreeBSD versions, Suricata versions, pfSense/OPNsense
  layouts and Linux are untested; Linux is not a goal.
- Inline IPS setups: untested, not supported.
- Rule sources other than ET Open and a free source (`oisf/trafficid`): the
  paid ET Pro style key flow was rehearsed against the real servers with a
  made-up key only (it failed cleanly and everything was put back). A
  successful run with a real key is covered by unit tests, not by a live test.
- Snort's registered rules do **not** load in Suricata 8 (Suricata refuses
  some of their syntax). suritui does not offer them; a failed load is rolled
  back, but there is no point in trying.
- Silencing an alert from the alert screen (`s` / `S`) has unit tests and one
  live run on the router (one rule silenced for one source address, then
  logged and loaded without a restart). Only that one case was tried.
- The 120-second limit on refreshing the source list (the message
  "fetching the source list timed out") and the cap of 20,000 alerts per read
  (the status line then says how many older alerts were not loaded) have unit
  tests but were never triggered on a real router or VM.
- The installer's "put the old sudoers file back" path has not been triggered
  on a real machine.
- No human other than the author has read the code. The whole code base went
  through AI-assisted code reviews (Claude's cloud code review, run on the
  root helper, the core, the model and the screens separately); their findings
  were fixed. That is not a security audit. The helper runs as root: read
  `src/bin/suritui-admin.rs`, `src/admin.rs`, `src/update.rs` and
  `src/sources.rs` before you install it.

## Known limitations

- Text width is counted in characters, not display cells, so wide (CJK, emoji)
  characters can misalign columns.
- ssh (remote mode) runs with `ConnectTimeout=10`, `ServerAliveInterval=10` and
  `ServerAliveCountMax=3`, so an unreachable or hung router fails after about
  10 to 40 seconds, but the screen is still blocked until then.
- Alert data is limited to today plus the 14 rotated logs; there is no combined
  multi-day view.
- On narrow terminals the signature column shrinks first. The sidebar does not
  scroll: with more categories than rows, the extra ones are cut off.
- A rule change or source change takes about two minutes (the full rule set is
  rebuilt and checked first); the screen shows progress and cannot be left
  meanwhile.
