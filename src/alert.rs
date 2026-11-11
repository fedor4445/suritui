//! Parsing of Suricata eve.json alert lines.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub ts: String,
    pub iface: String,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub action: String,
    pub signature: String,
    pub sid: Option<u64>,
    pub rev: Option<u32>,
    pub severity: Option<u8>,
    pub et_severity: Option<String>,
    pub confidence: Option<String>,
    pub mitre: Option<String>,
    pub context: Option<String>,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Category {
    Et(String),
    Decoder,
    Other,
}

impl Category {
    pub fn label(&self) -> String {
        match self {
            Category::Et(w) => w.clone(),
            Category::Decoder => "SURICATA (decoder)".to_string(),
            Category::Other => "Other".to_string(),
        }
    }
}

fn text(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or("-").to_string()
}

fn endpoint(v: &Value, ip: &str, port: &str) -> String {
    let ip = text(v.get(ip));
    match v.get(port).and_then(Value::as_u64) {
        Some(p) if ip != "-" => format!("{ip}:{p}"),
        _ => ip,
    }
}

/// First string of a metadata array (or a plain string).
fn meta(md: Option<&Value>, key: &str) -> Option<String> {
    let v = md?.get(key)?;
    v.as_array()
        .and_then(|a| a.first())
        .unwrap_or(v)
        .as_str()
        .map(str::to_string)
}

pub fn parse_line(line: &str) -> Option<Alert> {
    let v: Value = serde_json::from_str(line).ok()?;
    if v.get("event_type")?.as_str()? != "alert" {
        return None;
    }
    let al = v.get("alert");
    let get = |k: &str| al.and_then(|a| a.get(k));
    let md = get("metadata");
    let mitre = match (
        meta(md, "mitre_technique_id"),
        meta(md, "mitre_technique_name"),
    ) {
        (Some(i), Some(n)) => Some(format!("{i} {n}")),
        (Some(i), None) => Some(i),
        (None, Some(n)) => Some(n),
        (None, None) => None,
    };
    let context = [("dns", "rrname"), ("tls", "sni"), ("http", "hostname")]
        .iter()
        .find_map(|(o, k)| v.get(*o)?.get(*k)?.as_str().map(str::to_string));
    Some(Alert {
        ts: text(v.get("timestamp")),
        iface: text(v.get("in_iface")),
        src: endpoint(&v, "src_ip", "src_port"),
        dst: endpoint(&v, "dest_ip", "dest_port"),
        proto: text(v.get("proto")),
        action: text(get("action")),
        signature: text(get("signature")),
        sid: get("signature_id").and_then(Value::as_u64),
        rev: get("rev")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        severity: get("severity")
            .and_then(Value::as_u64)
            .and_then(|n| u8::try_from(n).ok()),
        et_severity: meta(md, "signature_severity"),
        confidence: meta(md, "confidence"),
        mitre,
        context,
        raw: line.to_string(),
    })
}

pub fn category(signature: &str) -> Category {
    if signature.starts_with("SURICATA ") {
        return Category::Decoder;
    }
    if let Some(rest) = signature.strip_prefix("ET ") {
        if let Some(word) = rest.split_whitespace().next() {
            return Category::Et(word.to_string());
        }
    }
    Category::Other
}

pub fn is_informational(a: &Alert) -> bool {
    match &a.et_severity {
        Some(s) => s == "Informational",
        None => a.severity == Some(3),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"{"timestamp":"2026-01-02T03:04:05.000000-0500","in_iface":"eth0","event_type":"alert","src_ip":"192.0.2.10","src_port":5555,"dest_ip":"198.51.100.20","dest_port":53,"proto":"UDP","alert":{"action":"allowed","gid":1,"signature_id":9000001,"rev":2,"signature":"ET DNS Query for .cc TLD","category":"Potentially Bad Traffic","severity":2,"metadata":{"signature_severity":["Major"],"confidence":["High"],"mitre_technique_id":["T1219"],"mitre_technique_name":["Remote_Access_Software"]}},"dns":{"rrname":"example.cc"}}"#;

    const BARE: &str = r#"{"timestamp":"2026-01-02T03:04:05.000000-0500","event_type":"alert","src_ip":"192.0.2.1","dest_ip":"203.0.113.2","alert":{"signature":"SURICATA Ethertype unknown"}}"#;

    fn alert_with(sev: Option<u8>, et: Option<&str>) -> Alert {
        let mut a = parse_line(BARE).unwrap();
        a.severity = sev;
        a.et_severity = et.map(String::from);
        a
    }

    #[test]
    fn parses_full_alert() {
        let a = parse_line(FULL).unwrap();
        assert_eq!(a.ts, "2026-01-02T03:04:05.000000-0500");
        assert_eq!(a.iface, "eth0");
        assert_eq!(a.src, "192.0.2.10:5555");
        assert_eq!(a.dst, "198.51.100.20:53");
        assert_eq!(a.proto, "UDP");
        assert_eq!(a.action, "allowed");
        assert_eq!(a.signature, "ET DNS Query for .cc TLD");
        assert_eq!(a.sid, Some(9000001));
        assert_eq!(a.rev, Some(2));
        assert_eq!(a.severity, Some(2));
        assert_eq!(a.et_severity.as_deref(), Some("Major"));
        assert_eq!(a.confidence.as_deref(), Some("High"));
        assert_eq!(a.mitre.as_deref(), Some("T1219 Remote_Access_Software"));
        assert_eq!(a.context.as_deref(), Some("example.cc"));
        assert_eq!(a.raw, FULL);
    }

    #[test]
    fn parses_alert_without_metadata_or_ports() {
        let a = parse_line(BARE).unwrap();
        assert_eq!(a.src, "192.0.2.1");
        assert_eq!(a.dst, "203.0.113.2");
        assert_eq!(a.iface, "-");
        assert_eq!(a.proto, "-");
        assert_eq!(a.action, "-");
        assert_eq!(a.sid, None);
        assert_eq!(a.rev, None);
        assert_eq!(a.severity, None);
        assert_eq!(a.et_severity, None);
        assert_eq!(a.confidence, None);
        assert_eq!(a.mitre, None);
        assert_eq!(a.context, None);
    }

    #[test]
    fn context_falls_back_to_tls_then_http() {
        let tls = r#"{"event_type":"alert","alert":{"signature":"x"},"tls":{"sni":"tls.example"},"http":{"hostname":"h.example"}}"#;
        assert_eq!(
            parse_line(tls).unwrap().context.as_deref(),
            Some("tls.example")
        );
        let http =
            r#"{"event_type":"alert","alert":{"signature":"x"},"http":{"hostname":"h.example"}}"#;
        assert_eq!(
            parse_line(http).unwrap().context.as_deref(),
            Some("h.example")
        );
    }

    #[test]
    fn missing_signature_and_addresses_do_not_error() {
        let a = parse_line(r#"{"event_type":"alert"}"#).unwrap();
        assert_eq!(a.signature, "-");
        assert_eq!(a.src, "-");
        assert_eq!(a.dst, "-");
        assert_eq!(a.ts, "-");
    }

    #[test]
    fn non_alert_event_is_none() {
        assert!(parse_line(r#"{"event_type":"dns","src_ip":"192.0.2.1"}"#).is_none());
        assert!(parse_line(r#"{"no_event_type":true}"#).is_none());
    }

    #[test]
    fn malformed_json_is_none() {
        assert!(parse_line("{not json").is_none());
        assert!(parse_line("").is_none());
        assert!(parse_line("[1,2]").is_none());
    }

    #[test]
    fn category_et() {
        assert_eq!(
            category("ET DNS Query for .cc TLD"),
            Category::Et("DNS".into())
        );
        assert_eq!(category("ET DNS Query for .cc TLD").label(), "DNS");
    }

    #[test]
    fn category_decoder() {
        assert_eq!(category("SURICATA Ethertype unknown"), Category::Decoder);
        assert_eq!(Category::Decoder.label(), "SURICATA (decoder)");
    }

    #[test]
    fn category_other_cases() {
        for s in [
            "ET",
            "ET ",
            "ETPRO MALWARE x",
            "",
            "et dns",
            "SURICATA",
            "SURICATAfoo bar",
            "GPL ICMP",
            "-",
        ] {
            assert_eq!(category(s), Category::Other, "{s:?}");
        }
        assert_eq!(Category::Other.label(), "Other");
    }

    #[test]
    fn informational_by_et_severity() {
        assert!(is_informational(&alert_with(
            Some(1),
            Some("Informational")
        )));
        assert!(!is_informational(&alert_with(Some(3), Some("Minor"))));
    }

    #[test]
    fn informational_falls_back_to_severity_3_without_et_severity() {
        assert!(is_informational(&alert_with(Some(3), None)));
        assert!(!is_informational(&alert_with(Some(2), None)));
        assert!(!is_informational(&alert_with(None, None)));
    }

    #[test]
    fn major_is_not_informational() {
        assert!(!is_informational(&parse_line(FULL).unwrap()));
        assert!(!is_informational(&alert_with(Some(3), Some("Major"))));
    }
}
