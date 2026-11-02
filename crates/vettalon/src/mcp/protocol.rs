//! Serial JSON-RPC transport with bounded line buffering.

use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

pub const MAX_LINE_BYTES: usize = 1024 * 1024;
const VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
use super::tools::NOTICE;

/// Business operations may be replaced without launching a sandbox or process.
pub trait Backend {
    fn call(&mut self, name: &str, arguments: Value) -> Result<Value, String>;
}

pub struct State<B> {
    pub initialized: bool,
    pub backend: B,
}

impl<B> State<B> {
    pub fn new(backend: B) -> Self {
        Self {
            initialized: false,
            backend,
        }
    }
}

fn error(id: Value, code: i32, message: &str) -> String {
    json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,"message":message}}).to_string()
}

fn tool_result(value: Result<Value, String>) -> Value {
    let is_error = value.is_err();
    let mut payload = match value {
        Ok(Value::Object(object)) => Value::Object(object),
        Ok(value) => json!({"data":value}),
        Err(message) => json!({"error":message}),
    };
    if is_error {
        super::tools::sanitize(&mut payload);
    }
    payload["untrusted_data"] = json!(true);
    payload["notice"] = json!(NOTICE);
    let result = json!({"content":[{"type":"text","text":payload.to_string()}],"isError":is_error});
    if result.to_string().len() > MAX_LINE_BYTES {
        return tool_result(Err(
            "Tool result exceeds 1 MiB; use narrower pagination or a narrower query.".into(),
        ));
    }
    result
}

/// Handle exactly one message. Notifications never produce a reply.
pub fn handle_message<B: Backend>(state: &mut State<B>, input: &str) -> Option<String> {
    if input.len() > MAX_LINE_BYTES {
        return Some(error(Value::Null, -32600, "Message exceeds 1 MiB"));
    }
    let message: Value = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(_) => return Some(error(Value::Null, -32700, "Parse error")),
    };
    let Some(object) = message.as_object() else {
        return Some(error(Value::Null, -32600, "Expected one JSON-RPC request"));
    };
    let id = object.get("id").cloned();
    let valid_id = id
        .as_ref()
        .is_none_or(|id| id.is_null() || id.is_string() || id.is_number());
    if !valid_id {
        return Some(error(Value::Null, -32600, "Invalid request id"));
    }
    let response_id = id.clone().unwrap_or(Value::Null);
    let reply = |code, message| {
        id.as_ref()
            .map(|_| error(response_id.clone(), code, message))
    };
    if object.get("jsonrpc") != Some(&json!("2.0"))
        || !object.get("method").is_some_and(Value::is_string)
        || object
            .keys()
            .any(|key| !["jsonrpc", "id", "method", "params"].contains(&key.as_str()))
    {
        return Some(error(
            response_id.clone(),
            -32600,
            "Invalid JSON-RPC request",
        ));
    }
    let method = object["method"].as_str().unwrap_or_default();
    if !state.initialized && !["initialize", "ping"].contains(&method) {
        return reply(-32600, "Initialize the server first");
    }
    if ![
        "initialize",
        "ping",
        "notifications/initialized",
        "notifications/cancelled",
        "tools/list",
        "tools/call",
    ]
    .contains(&method)
    {
        return reply(-32601, "Method not found");
    }
    let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
    let Some(params_object) = params.as_object() else {
        return reply(-32602, "Params must be an object");
    };
    let result = match method {
        "initialize" => {
            if !params_object
                .get("protocolVersion")
                .is_some_and(Value::is_string)
                || params_object
                    .get("capabilities")
                    .is_some_and(|value| !value.is_object())
                || params_object
                    .get("clientInfo")
                    .is_some_and(|value| !value.is_object())
                || params_object.keys().any(|key| {
                    !["protocolVersion", "capabilities", "clientInfo"].contains(&key.as_str())
                })
            {
                return reply(-32602, "Invalid initialize params");
            }
            let requested = params_object["protocolVersion"]
                .as_str()
                .unwrap_or_default();
            let version = if VERSIONS.contains(&requested) {
                requested
            } else {
                VERSIONS[0]
            };
            state.initialized = true;
            json!({"protocolVersion":version,"capabilities":{"tools":{}},
                "serverInfo":{"name":"vettalon","version":env!("CARGO_PKG_VERSION")}})
        }
        "ping" | "notifications/initialized" => {
            if !params_object.is_empty() {
                return reply(-32602, "Expected empty params");
            }
            json!({})
        }
        // Work is serial; cancellation cannot interrupt an in-flight operation.
        "notifications/cancelled" => json!({}),
        "tools/list" => {
            if !params_object.is_empty() {
                return reply(-32602, "Expected empty params");
            }
            json!({"tools":super::tools::schemas()})
        }
        "tools/call" => {
            if params_object
                .keys()
                .any(|key| !["name", "arguments"].contains(&key.as_str()))
                || !params_object.get("name").is_some_and(Value::is_string)
            {
                return reply(-32602, "Invalid tool call params");
            }
            let name = params_object["name"].as_str().unwrap_or_default();
            let arguments = params_object
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let known = super::tools::schemas()
                .iter()
                .any(|tool| tool["name"] == name);
            if !known {
                tool_result(Err("Unknown tool".into()))
            } else {
                if super::tools::validate_args(name, &arguments).is_err() {
                    return reply(-32602, "Invalid tool arguments");
                }
                tool_result(state.backend.call(name, arguments))
            }
        }
        _ => return reply(-32601, "Method not found"),
    };
    id.map(|id| json!({"jsonrpc":"2.0","id":id,"result":result}).to_string())
}

/// Drain an oversized line without retaining its remaining bytes.
fn read_line<R: BufRead>(reader: &mut R, line: &mut Vec<u8>) -> io::Result<Option<bool>> {
    line.clear();
    let mut oversized = false;
    let mut received = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(received.then_some(oversized));
        }
        received = true;
        let end = buffer.iter().position(|byte| *byte == b'\n');
        let count = end.unwrap_or(buffer.len());
        if !oversized {
            if line.len().saturating_add(count) > MAX_LINE_BYTES {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(&buffer[..count]);
            }
        }
        reader.consume(count + usize::from(end.is_some()));
        if end.is_some() {
            return Ok(Some(oversized));
        }
    }
}

/// EOF is a normal exit; stdout contains only complete JSON lines.
pub fn serve<B: Backend, R: BufRead, W: Write>(
    state: &mut State<B>,
    mut reader: R,
    mut writer: W,
) -> io::Result<()> {
    let mut line = Vec::new();
    while let Some(oversized) = read_line(&mut reader, &mut line)? {
        let response = if oversized {
            Some(error(Value::Null, -32600, "Message exceeds 1 MiB"))
        } else {
            match std::str::from_utf8(&line) {
                Ok(message) => handle_message(state, message),
                Err(_) => Some(error(Value::Null, -32700, "Parse error")),
            }
        };
        if let Some(response) = response {
            writeln!(writer, "{response}")?;
            writer.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Default)]
    struct Fake {
        calls: usize,
    }

    impl Backend for Fake {
        fn call(&mut self, _: &str, _: Value) -> Result<Value, String> {
            self.calls += 1;
            Err("Unknown finding".into())
        }
    }

    fn request(state: &mut State<Fake>, method: &str, params: Value) -> Value {
        let raw = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        serde_json::from_str(&handle_message(state, &raw.to_string()).unwrap()).unwrap()
    }

    fn initialized() -> State<Fake> {
        State {
            initialized: true,
            backend: Fake::default(),
        }
    }

    #[test]
    fn serialized_tool_result_cap_includes_json_escaping() {
        let input = json!({"text": "\"".repeat(MAX_LINE_BYTES / 3)});
        assert!(input.to_string().len() < MAX_LINE_BYTES);
        let result = tool_result(Ok(input));
        assert_eq!(result["isError"], true);
        assert!(result.to_string().contains("narrower pagination"));
        assert!(result.to_string().len() <= MAX_LINE_BYTES);
        let small = tool_result(Ok(json!({"text":"small"})));
        assert_eq!(small["isError"], false);
    }

    #[test]
    fn negotiates_every_supported_version_and_unknown() {
        for version in VERSIONS.into_iter().chain(["unknown"]) {
            let mut state = State::new(Fake::default());
            let response = request(&mut state, "initialize", json!({"protocolVersion":version}));
            assert_eq!(
                response["result"]["protocolVersion"],
                if version == "unknown" {
                    VERSIONS[0]
                } else {
                    version
                }
            );
            assert_eq!(response["result"]["capabilities"], json!({"tools":{}}));
            assert_eq!(response["result"]["serverInfo"]["name"], "vettalon");
            assert!(state.initialized);
        }
    }

    #[test]
    fn refuses_before_initialize_except_ping() {
        let mut state = State::new(Fake::default());
        assert!(
            request(&mut state, "ping", json!({}))
                .get("result")
                .is_some()
        );
        assert_eq!(
            request(&mut state, "tools/list", json!({}))["error"]["code"],
            -32600
        );
        assert!(!state.initialized);
    }

    #[test]
    fn errors_have_required_codes_and_preserve_ids() {
        let mut state = initialized();
        let parse: Value = serde_json::from_str(&handle_message(&mut state, "{").unwrap()).unwrap();
        assert_eq!(parse["error"]["code"], -32700);
        assert_eq!(parse["id"], Value::Null);
        assert_eq!(
            request(&mut state, "unknown", json!({}))["error"]["code"],
            -32601
        );
        assert_eq!(
            request(&mut state, "ping", json!([]))["error"]["code"],
            -32602
        );
        assert_eq!(
            request(
                &mut state,
                "tools/call",
                json!({"name":"vettalon_report_summary","arguments":{"path":"/tmp"}})
            )["error"]["code"],
            -32602
        );
        let response: Value = serde_json::from_str(
            &handle_message(&mut state, r#"{"jsonrpc":"1.0","id":"a","method":"ping"}"#).unwrap(),
        )
        .unwrap();
        assert_eq!(response["error"]["code"], -32600);
        assert_eq!(response["id"], "a");
    }

    #[test]
    fn notifications_never_reply_including_unknown_and_invalid_params() {
        let mut state = initialized();
        for method in [
            "notifications/initialized",
            "notifications/cancelled",
            "unknown",
            "ping",
        ] {
            for params in [json!({}), json!([])] {
                let raw = json!({"jsonrpc":"2.0","method":method,"params":params});
                assert!(handle_message(&mut state, &raw.to_string()).is_none());
            }
        }
    }

    #[test]
    fn malformed_objects_without_ids_are_invalid_requests() {
        assert_eq!(
            request(&mut initialized(), "unknown", json!([]))["error"]["code"],
            -32601
        );
        for raw in ["{}", r#"{"jsonrpc":"2.0","method":1}"#] {
            let response: Value =
                serde_json::from_str(&handle_message(&mut initialized(), raw).unwrap()).unwrap();
            assert_eq!(response["id"], Value::Null);
            assert_eq!(response["error"]["code"], -32600);
        }
    }

    #[test]
    fn batches_and_oversized_messages_are_refused() {
        let mut state = initialized();
        for input in ["[]".to_owned(), " ".repeat(MAX_LINE_BYTES + 1)] {
            let response: Value =
                serde_json::from_str(&handle_message(&mut state, &input).unwrap()).unwrap();
            assert_eq!(response["error"]["code"], -32600);
            assert_eq!(response["id"], Value::Null);
        }
    }

    #[test]
    fn bounded_transport_drains_oversized_lines_and_keeps_running() {
        let mut input = vec![b'x'; MAX_LINE_BYTES * 3];
        input.extend_from_slice(b"\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}");
        let mut output = Vec::new();
        serve(&mut initialized(), Cursor::new(input), &mut output).unwrap();
        let responses: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["error"]["code"], -32600);
        assert_eq!(responses[1]["id"], 2);
        let mut output = Vec::new();
        serve(
            &mut initialized(),
            Cursor::new(Vec::<u8>::new()),
            &mut output,
        )
        .unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn tool_errors_mask_sensitive_text_and_bound_report_derived_messages() {
        let result = tool_result(Err(format!("AKIAIOSFODNN7EXAMPLE {}", "x".repeat(20_000))));
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"));
        let payload: Value = serde_json::from_str(text).unwrap();
        assert!(payload["error"].as_str().unwrap().len() <= 16 * 1024);
    }

    #[test]
    fn business_errors_are_normal_untrusted_tool_results() {
        let mut state = initialized();
        for name in ["unknown", "vettalon_get_finding"] {
            let response = request(
                &mut state,
                "tools/call",
                json!({"name":name,"arguments":{"finding":"missing"}}),
            );
            assert_eq!(response["result"]["isError"], true);
            let payload: Value =
                serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                    .unwrap();
            assert_eq!(payload["untrusted_data"], true);
            assert_eq!(payload["notice"], NOTICE);
        }
        assert_eq!(state.backend.calls, 1);
    }

    fn assert_no_paths(value: &Value) {
        if let Some(properties) = value.get("properties").and_then(Value::as_object) {
            for (name, property) in properties {
                let name = name.to_ascii_lowercase();
                assert!(
                    ![
                        "path",
                        "directory",
                        "repo",
                        "report",
                        "filename",
                        "image",
                        "command"
                    ]
                    .iter()
                    .any(|part| name.contains(part)),
                    "path-like property: {name}"
                );
                assert_no_paths(property);
            }
            assert_eq!(value["additionalProperties"], false);
        }
        if let Some(items) = value.get("items") {
            assert_no_paths(items);
        }
    }

    #[test]
    fn schema_snapshot_has_seven_closed_tools_and_no_path_arguments() {
        let response = request(&mut initialized(), "tools/list", json!({}));
        let tools = response["result"]["tools"].as_array().unwrap();
        let names: Vec<_> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "vettalon_report_summary",
                "vettalon_list_findings",
                "vettalon_get_finding",
                "vettalon_fix_brief",
                "vettalon_reproduce",
                "vettalon_check_fix",
                "vettalon_suggest_noise"
            ]
        );
        for tool in tools {
            assert_no_paths(&tool["inputSchema"]);
            assert!(tool["inputSchema"]["required"].is_array());
            assert_eq!(tool["annotations"]["destructiveHint"], false);
            assert_eq!(tool["annotations"]["openWorldHint"], false);
            assert!(tool["annotations"]["readOnlyHint"].is_boolean());
        }
    }
}
