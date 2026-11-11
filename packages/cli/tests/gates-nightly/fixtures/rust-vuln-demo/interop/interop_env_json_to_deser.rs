// IL-57 — JSON env blob → YAML parse sink (IL-5 config frontier).
pub fn load(user_blob: &str) {
    let node: serde_json::Value = serde_json::from_str(user_blob).unwrap_or_default();
    let raw = node.get("payload").and_then(|v| v.as_str()).unwrap_or("");
    let _: serde_json::Value = serde_yaml::from_str(raw).unwrap_or_default();
}
