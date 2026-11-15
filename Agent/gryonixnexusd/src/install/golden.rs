//! Test helper: reads the Swift-dumped catalog golden.

use serde_json::Value;

fn golden() -> Vec<Value> {
    let path = format!("{}/../../Android/catalog/src/test/resources/swift-catalog-golden.json", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing {path}: {err}"));
    serde_json::from_str(&text).expect("golden json")
}

/// The first setup step Swift generates for a service
pub fn setup_step(id: &str) -> String {
    golden()
        .into_iter()
        .find(|service| service["id"] == id)
        .and_then(|service| service["setupSteps"][0].as_str().map(str::to_string))
        .unwrap_or_else(|| panic!("{id} is not in the golden"))
}
