//! Client side: `WslHost` implements `ToolHost` by forwarding every tool call to the executor, after a LOCAL authorization too
//! (defence in depth: a compromised executor cannot widen what the host agreed to).
use super::{protocol::*, wsl::Wsl};
use crate::config::{Settings, ORCHESTRATOR_ID};
use crate::error::{Error, Result, SecResult, SecurityError};
use crate::security::{
    audit::{AuditLogger, Event, Rec},
    runtime::{PermissionPolicy, SessionState, ToolDef, ToolHost, ToolOutcome},
    secrets::SecretRedactor,
};
use crate::util::{clip, expanduser};

use serde_json::{json, Value};
use std::{
    io::{BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{channel, Receiver, RecvTimeoutError},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

struct Conn {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<std::result::Result<String, String>>,
    next_id: u64,
}

pub struct ExecutorClient {
    conn: Mutex<Conn>,
    stderr_tail: Arc<Mutex<String>>,
    call_timeout: Duration,
}

impl ExecutorClient {
    pub fn spawn(
        argv: &[String],
        startup: Duration,
        call_timeout: Duration,
        max_bytes: usize,
    ) -> Result<(ExecutorClient, Value)> {
        let mut child = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                Error::internal("OSError", format!("unable to launch executor: {err}"))
            })?;

        let (stdin, stdout, stderr) = (
            child.stdin.take().unwrap(),
            child.stdout.take().unwrap(),
            child.stderr.take().unwrap(),
        );

        let tail = Arc::new(Mutex::new(String::new()));
        let t2 = tail.clone();

        thread::spawn(move || {
            use std::io::Read;

            let mut child_stderr = stderr;
            let mut bytes = [0u8; 2048];
            while let Ok(readed_len) = child_stderr.read(&mut bytes) {
                if readed_len == 0 {
                    break;
                }

                let mut child_tail = t2.lock().unwrap();
                child_tail.push_str(&String::from_utf8_lossy(&bytes[..readed_len]));
                let l = child_tail.len();

                if l > 4000 {
                    *child_tail = child_tail[l - 4000..].to_string();
                }
            }
        });

        let (tx, rx) = channel();
        thread::spawn(move || {
            let mut buff_r = BufReader::new(stdout);
            loop {
                match read_line_limited(&mut buff_r, max_bytes) {
                    Ok(Some(line)) => {
                        if tx.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        let _ = tx.send(Err(err.to_string()));
                        break;
                    }
                }
            }
        });

        let exec_client = ExecutorClient {
            conn: Mutex::new(Conn {
                child,
                stdin,
                rx,
                next_id: 1,
            }),
            stderr_tail: tail,
            call_timeout,
        };

        let hello = exec_client.request_with(json!({"op": "hello"}), startup)?;
        Ok((exec_client, hello))
    }

    fn request_with(&self, mut req: Value, timeout: Duration) -> Result<Value> {
        let mut conn = self.conn.lock().unwrap();
        let id = conn.next_id;
        conn.next_id += 1;
        req["id"] = json!(id);

        let fn_fail = |conn_target: &mut Conn, why: &str| -> Error {
            let _ = conn_target.child.kill();
            Error::internal(
                "ExecutorError",
                format!(
                    "{why} - executor stderr : {}",
                    clip(self.stderr_tail.lock().unwrap().trim(), 400)
                ),
            )
        };

        if conn
            .stdin
            .write_all(encode(&req).as_bytes())
            .and_then(|_| conn.stdin.flush())
            .is_err()
        {
            return Err(fn_fail(&mut conn, "executor unreachable"));
        }

        match conn.rx.recv_timeout(timeout) {
            Ok(Ok(line)) => {
                let value = decode(&line)?;

                if value.get("id") != Some(&json!(id)) {
                    return Err(fn_fail(&mut conn, "desynchronized response"));
                }

                if value.get("ok") == Some(&json!(false)) {
                    return Err(Error::internal(
                        "ExecutorError",
                        value
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("Error")
                            .to_string(),
                    ));
                }
                Ok(value)
            }
            Ok(Err(m)) => Err(fn_fail(&mut conn, &m)),
            Err(RecvTimeoutError::Timeout) => Err(fn_fail(&mut conn, "deadline exceeded")),
            Err(RecvTimeoutError::Disconnected) => Err(fn_fail(&mut conn, "arrested perpetrator")),
        }
    }

    pub fn request(&self, req: Value) -> Result<Value> {
        self.request_with(req, self.call_timeout)
    }
}

impl Drop for ExecutorClient {
    fn drop(&mut self) {
        if let Ok(mut conn) = self.conn.lock() {
            let _ = conn
                .stdin
                .write_all(encode(&json!({"op": "shutdown"})).as_bytes());
            let _ = conn.child.kill();
        }
    }
}

pub struct WslHost {
    settings: Arc<Settings>,
    policy: PermissionPolicy,
    audit: AuditLogger,
    client: ExecutorClient,
    session: Mutex<SessionState>,
    redactor: SecretRedactor,
    pub info: Value,
}

impl WslHost {
    pub fn connect(settings: Arc<Settings>) -> Result<WslHost> {
        let wsl = Wsl::new(&settings);
        let argv = wsl.executor_argv()?;
        let cfg = &settings.deployment.wsl;

        let (client, hello) = ExecutorClient::spawn(
            &argv,
            Duration::from_secs_f64(cfg.startup_timeout_s),
            Duration::from_secs_f64(cfg.call_timeout_s),
            cfg.max_message_bytes,
        )?;

        if hello.get("protocol").and_then(Value::as_u64) != Some(PROTOCOL_VERSION) {
            return Err(Error::config(
                "protocol version incompatible with the executor: run `wsl sync` again",
            ));
        }

        if hello.get("config_sha256").and_then(Value::as_str) != Some(&config_hash(&settings)) {
            return Err(Error::config(
                "The configuration differs between the host and WSL: run `agwo wsl sync` again.",
            ));
        }

        let redactor = Arc::new(SecretRedactor::new(None));
        let audit = AuditLogger::new(
            Some(expanduser(&settings.deployment.client_audit_path)),
            redactor,
            settings.permissions.audit.max_field_chars,
        );

        Ok(WslHost {
            policy: PermissionPolicy::new(&settings),
            settings,
            audit,
            client,
            session: Mutex::new(SessionState::default()),
            redactor: SecretRedactor::new(None),
            info: hello,
        })
    }
}

impl ToolHost for WslHost {
    fn settings(&self) -> &Settings {
        &self.settings
    }

    fn policy(&self) -> &PermissionPolicy {
        &self.policy
    }

    fn audit(&self) -> &AuditLogger {
        &self.audit
    }

    fn backend_name(&self) -> String {
        format!(
            "wsl ({} {})",
            self.info["os"].as_str().unwrap_or("?"),
            self.info["arch"].as_str().unwrap_or("?")
        )
    }

    fn tool_defs(&self, agent_id: &str) -> SecResult<Vec<ToolDef>> {
        if agent_id == ORCHESTRATOR_ID {
            return Ok(vec![]);
        }

        let allowed = self.policy.tools_for(agent_id)?;
        let req = self
            .client
            .request(json!({"op": "tool_defs", "agent": agent_id}))
            .map_err(|err| SecurityError::permission("executor_error", err.to_string()))?;

        Ok(req["defs"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|d| {
                let name = d["name"].as_str()?.to_string();
                allowed.contains(&name).then(|| ToolDef {
                    name,
                    description: d["description"].as_str().unwrap_or("").into(),
                    schema: d["schema"].clone(),
                })
            })
            .collect())
    }

    fn call(&self, agent_id: &str, tool_id: &str, args: &Value) -> ToolOutcome {
        if let Err(err) = self.policy.authorize(agent_id, tool_id) {
            self.audit.record(Rec {
                agent: agent_id,
                tool: tool_id,
                decision: "deny",
                code: Some(&err.code),
                reason: Some(&err.reason),
                ..Default::default()
            });

            return ToolOutcome::Failure {
                message: format!("REJECTED by security policy: {}", err.reason),
                code: err.code,
            };
        }

        match self
            .client
            .request(json!({"op": "tool", "agent": agent_id, "tool": tool_id, "args": args}))
        {
            Err(err) => {
                self.audit.record(Rec {
                    agent: agent_id,
                    tool: tool_id,
                    decision: "error",
                    code: Some("executor_error"),
                    ..Default::default()
                });

                ToolOutcome::Failure {
                    message: format!(
                        "REJECTED by security policy: {}",
                        clip(&err.to_string(), 200)
                    ),
                    code: "executor_error".into(),
                }
            }
            Ok(value) => {
                for ev in value["audit"].as_array().into_iter().flatten() {
                    if let Some(map) = ev.as_object() {
                        self.audit.ingest(&Event::from_iter(map.clone()), "wsl");
                    }
                }

                let mut session_state = self.session.lock().unwrap();

                for url in value["session"]["seen_urls"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    session_state.seen_urls.insert(url.to_string());
                }

                session_state.created_files = value["session"]["created_files"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|val| val.as_str().map(String::from))
                    .collect();

                let outcome = &value["outcome"];
                if outcome["ok"] == json!(true) {
                    ToolOutcome::Ok(
                        self.redactor
                            .redact(outcome["text"].as_str().unwrap_or(""))
                            .into_owned(),
                    )
                } else {
                    ToolOutcome::Failure {
                        message: outcome["message"].as_str().unwrap_or("").into(),
                        code: outcome["code"].as_str().unwrap_or("tool_error").into(),
                    }
                }
            }
        }
    }

    fn session(&self) -> SessionState {
        self.session.lock().unwrap().clone()
    }

    fn read_text(&self, path: &str) -> SecResult<String> {
        let response = self
            .client
            .request(json!({"op": "read_text", "path": path}))
            .map_err(|err| SecurityError::path("executor_error", err.to_string()))?;

        Ok(response["text"].as_str().unwrap_or("").to_string())
    }

    fn contains_secret(&self, text: &str) -> bool {
        self.redactor.contains_secret(text)
    }
}
