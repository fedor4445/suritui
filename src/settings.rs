//! A read-only summary of suricata.yaml for the Settings screen. No YAML
//! library: a line scanner that only looks for the handful of facts a person
//! asks about, and says "not set" otherwise.

fn strip_comment(l: &str) -> &str {
    if l.trim_start().starts_with('#') {
        return "";
    }
    match l.find(" #") {
        Some(i) => &l[..i],
        None => l,
    }
}

fn indent(l: &str) -> usize {
    l.len() - l.trim_start().len()
}

fn unquote(v: &str) -> String {
    v.trim().trim_matches('"').trim_matches('\'').to_string()
}

/// The lines under a top-level `key:` (indent 0), up to the next top-level key.
fn block<'a>(lines: &[&'a str], key: &str) -> Vec<&'a str> {
    let head = format!("{key}:");
    let Some(start) = lines.iter().position(|l| strip_comment(l).trim_end() == head || strip_comment(l).starts_with(&format!("{head} "))) else {
        return Vec::new();
    };
    lines[start + 1..]
        .iter()
        .take_while(|l| {
            let c = strip_comment(l);
            c.trim().is_empty() || indent(c) > 0
        })
        .copied()
        .collect()
}

fn scalar(lines: &[&str], key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    lines.iter().find_map(|l| {
        let c = strip_comment(l);
        (indent(c) == 0).then(|| c.strip_prefix(&prefix).map(unquote)).flatten().filter(|v| !v.is_empty())
    })
}

fn interfaces(lines: &[&str], section: &str) -> Vec<String> {
    block(lines, section)
        .iter()
        .filter_map(|l| strip_comment(l).trim().strip_prefix("- interface:").map(unquote))
        .filter(|i| i != "default")
        .collect()
}

fn var(lines: &[&str], name: &str) -> Option<String> {
    let prefix = format!("{name}:");
    block(lines, "vars").iter().find_map(|l| strip_comment(l).trim().strip_prefix(&prefix).map(unquote))
}

/// `(name, enabled)` of each entry under `outputs:`.
///
/// Only the outputs themselves count: entries at the indent of the first `- `,
/// and the `enabled:` that is a direct child of one. Deeper `- name:` lines
/// (eve-log's `types:` list) and their own `enabled:` keys are not outputs.
fn outputs(lines: &[&str]) -> Vec<(String, String)> {
    let b = block(lines, "outputs");
    let mut out: Vec<(String, String)> = Vec::new();
    let Some(top) = b.iter().map(|l| strip_comment(l)).find(|c| c.trim_start().starts_with("- ")).map(indent) else {
        return out;
    };
    // The indent of the current output's own keys, fixed by its first child line.
    let mut child: Option<usize> = None;
    for l in b {
        let c = strip_comment(l);
        let t = c.trim();
        if t.is_empty() {
            continue;
        }
        let at = indent(c);
        if at == top {
            child = None;
            if let Some(name) = t.strip_prefix("- ").and_then(|r| r.strip_suffix(':')) {
                out.push((name.trim().to_string(), String::new()));
            }
        } else if at > top {
            let level = *child.get_or_insert(at);
            if at == level {
                if let (Some(v), Some(last)) = (t.strip_prefix("enabled:"), out.last_mut()) {
                    if last.1.is_empty() {
                        last.1 = unquote(v);
                    }
                }
            }
        }
    }
    out
}

fn yes(v: &str) -> bool {
    matches!(v, "yes" | "true" | "on" | "auto")
}

/// Lines for the Settings screen.
pub fn summarize(path: &str, text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut r = vec![format!("Config file: {path}   (read-only: edit it by hand)"), String::new()];
    r.push("Capture sections in the file (the start command decides which one runs):".to_string());
    let mut any = false;
    for s in ["pcap", "af-packet", "netmap"] {
        let i = interfaces(&lines, s);
        if !i.is_empty() {
            any = true;
            r.push(format!("  {s}: {}", i.join(", ")));
        }
    }
    if !any {
        r.push("  none found".to_string());
    }
    r.push(String::new());
    r.push("Networks:".to_string());
    r.push(format!("  HOME_NET      {}", var(&lines, "HOME_NET").unwrap_or_else(|| "not set".into())));
    r.push(format!("  EXTERNAL_NET  {}", var(&lines, "EXTERNAL_NET").unwrap_or_else(|| "not set".into())));
    r.push(String::new());
    r.push("Rules:".to_string());
    let dir = scalar(&lines, "default-rule-path").unwrap_or_else(|| "not set".into());
    r.push(format!("  rule path        {dir}"));
    let files: Vec<String> = block(&lines, "rule-files")
        .iter()
        .filter_map(|l| strip_comment(l).trim().strip_prefix("- ").map(unquote))
        .collect();
    r.push(format!("  rule files       {}", if files.is_empty() { "none".to_string() } else { files.join(", ") }));
    r.push(format!(
        "  threshold file   {}",
        scalar(&lines, "threshold-file").unwrap_or_else(|| "default (threshold.config next to suricata.yaml)".into())
    ));
    r.push(format!(
        "  classification   {}",
        scalar(&lines, "classification-file").unwrap_or_else(|| "default".into())
    ));
    r.push(String::new());
    r.push("Logging:".to_string());
    r.push(format!("  log directory    {}", scalar(&lines, "default-log-dir").unwrap_or_else(|| "not set".into())));
    let outs = outputs(&lines);
    if !outs.is_empty() {
        let list: Vec<String> = outs
            .iter()
            .filter(|(_, e)| !e.is_empty())
            .map(|(n, e)| format!("{n} ({})", if yes(e) { "on" } else { "off" }))
            .collect();
        r.push(format!("  outputs          {}", list.join(", ")));
    }
    let uc = block(&lines, "unix-command");
    let enabled = uc
        .iter()
        .find_map(|l| strip_comment(l).trim().strip_prefix("enabled:").map(unquote))
        .unwrap_or_else(|| "not set".into());
    r.push(format!("  command socket   {enabled} (needed for live rule reloads)"));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    const Y: &str = "\
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: \"[172.16.0.0/12]\"
    #HOME_NET: \"any\"
    EXTERNAL_NET: \"!$HOME_NET\"
default-log-dir: /var/log/suricata/
outputs:
  - fast:
      enabled: no
  - eve-log:
      enabled: yes
      filetype: regular
      types:
        - alert:
            xff:
              enabled: no
        - anomaly:
            enabled: yes
  - stats:
      enabled: yes # comment
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  # - other.rules
# threshold-file: /etc/x
af-packet:
  - interface: eth0
  - interface: default
pcap:
  - interface: igb0
  - interface: \"igb2.40\"
  - interface: default
unix-command:
  enabled: auto
  filename: x
";

    #[test]
    fn summarizes_the_facts_people_ask_about() {
        let s = summarize("/etc/suricata.yaml", Y).join("\n");
        assert!(s.contains("pcap: igb0, igb2.40") && s.contains("af-packet: eth0"), "{s}");
        assert!(!s.contains("default,"), "{s}");
        assert!(s.contains("HOME_NET      [172.16.0.0/12]") && s.contains("EXTERNAL_NET  !$HOME_NET"), "{s}");
        assert!(s.contains("rule path        /var/lib/suricata/rules") && s.contains("rule files       suricata.rules"), "{s}");
        assert!(s.contains("threshold file   default"), "{s}");
        assert!(s.contains("log directory    /var/log/suricata/"), "{s}");
        assert!(s.contains("fast (off), eve-log (on), stats (on)"), "{s}");
        assert!(!s.contains("anomaly") && !s.contains("alert ("), "{s}");
        assert!(s.contains("command socket   auto"), "{s}");
        assert!(s.contains("read-only"));
    }

    #[test]
    fn missing_things_say_so_instead_of_failing() {
        let s = summarize("/x", "").join("\n");
        assert!(s.contains("none found") && s.contains("not set") && s.contains("rule files       none"), "{s}");
        let s = summarize("/x", "pcap:\n  - interface: eth9\nthreshold-file: /etc/t.conf\n").join("\n");
        assert!(s.contains("threshold file   /etc/t.conf") && s.contains("pcap: eth9"), "{s}");
    }

    #[test]
    fn commented_values_are_ignored() {
        let s = summarize("/x", "# default-log-dir: /nope\n  #HOME_NET: \"1\"\n").join("\n");
        assert!(!s.contains("/nope") && s.contains("HOME_NET      not set"), "{s}");
    }
}
