use serde_json::Value;

const REDACTED: &str = "***REDACTED***";
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "token",
    "secret",
    "master",
    "key",
    "authorization",
    "notes",
    "custom_fields",
];

pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, item) in map {
                if is_sensitive_key(key) {
                    out.insert(key.clone(), Value::String(REDACTED.to_owned()));
                } else {
                    out.insert(key.clone(), redact_json(item));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_json).collect()),
        other => other.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEYS.iter().any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::redact_json;
    use serde_json::json;

    #[test]
    fn redacts_sensitive_keys_recursively() {
        let input = json!({
            "password": "abc",
            "nested": {
                "token": "secret-token",
                "safe": 1
            },
            "arr": [
                { "master_key": "k" },
                { "value": "ok" }
            ]
        });
        let out = redact_json(&input);
        assert_eq!(out["password"], "***REDACTED***");
        assert_eq!(out["nested"]["token"], "***REDACTED***");
        assert_eq!(out["nested"]["safe"], 1);
        assert_eq!(out["arr"][0]["master_key"], "***REDACTED***");
        assert_eq!(out["arr"][1]["value"], "ok");
    }
}
