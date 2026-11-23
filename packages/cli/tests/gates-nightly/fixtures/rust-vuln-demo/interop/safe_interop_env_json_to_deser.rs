// SAFE — constant structured value only.
pub fn load() {
    let _: serde_json::Value = serde_json::from_str("{\"ok\":true}").unwrap_or_default();
}
