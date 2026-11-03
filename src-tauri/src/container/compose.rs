//! Compose projects. Compose has no API, so its commands run on the host,
//! as Portainer and Dockge run them. A project is found from the labels
//! Compose puts on every container it creates, so projects started by hand,
//! by CI or by another tool all show up; the same labels say where the
//! project's files are, which is what `up`, `down` and `restart` need.

use std::collections::BTreeMap;

use bollard::query_parameters as q;
use serde::{Deserialize, Serialize};

use super::{sh_quote, Host};

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub name: String,
    pub working_dir: Option<String>,
    pub config_files: Vec<String>,
    pub services: Vec<String>,
    pub running: usize,
    pub total: usize,
}

/// Projects from container labels: name, directory, files, services.
pub fn projects_from(containers: &[bollard::models::ContainerSummary]) -> Vec<Project> {
    let mut by_name: BTreeMap<String, Project> = BTreeMap::new();
    for c in containers {
        let Some(labels) = &c.labels else { continue };
        let Some(name) = labels.get("com.docker.compose.project") else { continue };
        let p = by_name.entry(name.clone()).or_insert_with(|| Project {
            name: name.clone(),
            working_dir: None,
            config_files: Vec::new(),
            services: Vec::new(),
            running: 0,
            total: 0,
        });
        if p.working_dir.is_none() {
            p.working_dir = labels.get("com.docker.compose.project.working_dir").cloned();
        }
        if p.config_files.is_empty() {
            if let Some(files) = labels.get("com.docker.compose.project.config_files") {
                p.config_files = files.split(',').map(str::trim).filter(|f| !f.is_empty()).map(String::from).collect();
            }
        }
        if let Some(s) = labels.get("com.docker.compose.service") {
            if !p.services.contains(s) {
                p.services.push(s.clone());
            }
        }
        p.total += 1;
        if c.state.as_ref().map(|s| s.to_string()) == Some("running".into()) {
            p.running += 1;
        }
    }
    let mut out: Vec<Project> = by_name.into_values().collect();
    for p in &mut out {
        p.services.sort();
    }
    out
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ComposeAction {
    Up,
    Down,
    Restart,
    Stop,
    Start,
    Pull,
}

impl ComposeAction {
    fn args(self) -> &'static str {
        match self {
            // Detached: the command returns once the project is up.
            ComposeAction::Up => "up -d",
            // Volumes stay: `down -v` deletes data and is never sent.
            ComposeAction::Down => "down",
            ComposeAction::Restart => "restart",
            ComposeAction::Stop => "stop",
            ComposeAction::Start => "start",
            ComposeAction::Pull => "pull",
        }
    }
}

/// The command line for an action on a project, every value quoted.
pub fn command(cli: &str, p: &Project, action: ComposeAction) -> String {
    let mut cmd = format!("{cli} compose --project-name {}", sh_quote(&p.name));
    if let Some(dir) = &p.working_dir {
        cmd.push_str(&format!(" --project-directory {}", sh_quote(dir)));
    }
    for f in &p.config_files {
        cmd.push_str(&format!(" -f {}", sh_quote(f)));
    }
    cmd.push(' ');
    cmd.push_str(action.args());
    cmd
}

impl Host {
    pub async fn projects(&self) -> Result<Vec<Project>, String> {
        let list = self
            .docker
            .list_containers(Some(q::ListContainersOptions { all: true, ..Default::default() }))
            .await
            .map_err(|e| e.to_string())?;
        Ok(projects_from(&list))
    }

    /// Run `action` on the project called `name`; returns what Compose printed.
    pub async fn compose(&self, name: &str, action: ComposeAction) -> Result<String, String> {
        self.writable()?;
        let projects = self.projects().await?;
        let p = projects.iter().find(|p| p.name == name).ok_or_else(|| format!("No Compose project called {name}"))?;
        // Compose prints its progress on stderr even when it succeeds.
        let o = self.shell.run(&command(self.engine.cli(), p, action), 600).await?;
        if !o.ok() {
            return Err(o.failure(&format!("compose {}", action.args())));
        }
        Ok(format!("{}{}", o.stdout, o.stderr))
    }
}
