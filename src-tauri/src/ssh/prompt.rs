//! Asking the user something while a connection logs in: a password, a key's
//! passphrase, a server's keyboard-interactive questions, a yes or no. Built
//! like the host-key question: an event to the window, the login parked on a
//! oneshot until the answer comes back, and the time it waits not counted
//! against the connect limit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use serde::Serialize;
use tauri::Emitter;

type Answers = Option<Vec<String>>;

fn pending() -> &'static Mutex<HashMap<String, tokio::sync::oneshot::Sender<Answers>>> {
    static P: OnceLock<Mutex<HashMap<String, tokio::sync::oneshot::Sender<Answers>>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How many questions are open now, so the connect limit can stop counting.
static OPEN: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn any_open() -> bool {
    OPEN.load(Ordering::SeqCst) > 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Kind {
    Password,
    Passphrase,
    /// The server's keyboard-interactive questions (one-time codes and the like).
    Keyboard,
    /// A yes or no (AddKeysToAgent ask).
    Confirm,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Field {
    pub text: String,
    /// Show what is typed (false for secrets).
    pub echo: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    prompt_id: String,
    host: String,
    port: u16,
    kind: Kind,
    title: String,
    instructions: String,
    fields: Vec<Field>,
}

/// Withdrawn however the question ends: answered, timed out, or the
/// connection dropped while it was open.
struct Open {
    id: String,
    app: tauri::AppHandle,
}

impl Drop for Open {
    fn drop(&mut self) {
        pending().lock().unwrap().remove(&self.id);
        OPEN.fetch_sub(1, Ordering::SeqCst);
        let _ = self.app.emit("ssh-auth-prompt-closed", &self.id);
    }
}

/// Ask, and wait for the answer. `None` when there is no window to ask in,
/// the user cancels, or nobody answers within ten minutes.
pub(crate) async fn ask(
    app: Option<&tauri::AppHandle>,
    host: &str,
    port: u16,
    kind: Kind,
    title: &str,
    instructions: &str,
    fields: Vec<Field>,
) -> Answers {
    let app = app?;
    let id = uuid::Uuid::new_v4().to_string();
    let (tx, rx) = tokio::sync::oneshot::channel();
    pending().lock().unwrap().insert(id.clone(), tx);
    OPEN.fetch_add(1, Ordering::SeqCst);
    let _open = Open { id: id.clone(), app: app.clone() };
    let payload = Payload {
        prompt_id: id,
        host: host.to_string(),
        port,
        kind,
        title: title.to_string(),
        instructions: instructions.to_string(),
        fields,
    };
    if app.emit("ssh-auth-prompt", &payload).is_err() {
        return None;
    }
    match tokio::time::timeout(std::time::Duration::from_secs(600), rx).await {
        Ok(Ok(answers)) => answers,
        _ => None,
    }
}

/// Something that can put a question to the user. The app's window is one;
/// a test has none, and passing none keeps the window code out of it.
pub(crate) trait Asker: Send + Sync {
    fn ask<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        kind: Kind,
        title: &'a str,
        instructions: &'a str,
        fields: Vec<Field>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Answers> + Send + 'a>>;

    /// A notice that needs no answer while the login waits on something
    /// else, as ssh's notify_start ("Confirm user presence for key …").
    fn notify_start(&self, _host: &str, _port: u16, _text: &str) {}

    /// The notice is over; `done` is said briefly, as notify_complete does.
    fn notify_complete(&self, _host: &str, _port: u16, _done: Option<&str>) {}
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Notice<'a> {
    host: &'a str,
    port: u16,
    /// Shown until the next notice; `None` takes it down.
    text: Option<&'a str>,
    /// Said briefly when it ends.
    done: Option<&'a str>,
}

impl Asker for tauri::AppHandle {
    fn ask<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        kind: Kind,
        title: &'a str,
        instructions: &'a str,
        fields: Vec<Field>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Answers> + Send + 'a>> {
        Box::pin(ask(Some(self), host, port, kind, title, instructions, fields))
    }

    fn notify_start(&self, host: &str, port: u16, text: &str) {
        let _ = self.emit("ssh-auth-notice", Notice { host, port, text: Some(text), done: None });
    }

    fn notify_complete(&self, host: &str, port: u16, done: Option<&str>) {
        let _ = self.emit("ssh-auth-notice", Notice { host, port, text: None, done });
    }
}

/// The window's answer (`None` = cancelled).
pub(crate) fn resolve(prompt_id: &str, answers: Answers) {
    if let Some(tx) = pending().lock().unwrap().remove(prompt_id) {
        let _ = tx.send(answers);
    }
}
