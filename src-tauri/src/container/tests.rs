use std::collections::HashMap;

use bollard::models::{ContainerSummary, ContainerSummaryStateEnum};

use super::compose::{command, projects_from, ComposeAction, Project};
use super::*;

/// Runs `sh -c 'printf %s <quoted>'` for real and returns what the shell saw.
#[cfg(unix)]
fn through_sh(s: &str) -> String {
    let out = std::process::Command::new("sh").arg("-c").arg(format!("printf %s {}", sh_quote(s))).output().unwrap();
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn quoting_leaves_plain_words_alone() {
    assert_eq!(sh_quote("web-1"), "web-1");
    assert_eq!(sh_quote("/srv/app/compose.yml"), "/srv/app/compose.yml");
}

/// Anything a shell could act on is quoted, so a name or a path from the
/// server (a container label, say) cannot run a command of its own.
#[test]
fn quoting_neutralises_shell_syntax() {
    for s in ["", "a b", "$(id)", "`id`", "x;id", "a'b", "a\"b", "*", "~root", "a\nb", "a&&b", "-rf /"] {
        let q = sh_quote(s);
        assert!(q.starts_with('\''), "{s:?} -> {q}");
        #[cfg(unix)]
        assert_eq!(through_sh(s), s, "the shell must see {s:?} unchanged");
    }
}

fn container(project: &str, service: &str, running: bool, dir: &str, files: &str) -> ContainerSummary {
    let mut labels = HashMap::new();
    labels.insert("com.docker.compose.project".into(), project.into());
    labels.insert("com.docker.compose.service".into(), service.into());
    labels.insert("com.docker.compose.project.working_dir".into(), dir.into());
    labels.insert("com.docker.compose.project.config_files".into(), files.into());
    ContainerSummary {
        labels: Some(labels),
        state: Some(if running { ContainerSummaryStateEnum::RUNNING } else { ContainerSummaryStateEnum::EXITED }),
        ..Default::default()
    }
}

#[test]
fn projects_come_from_compose_labels() {
    let list = vec![
        container("shop", "web", true, "/srv/shop", "/srv/shop/compose.yml,/srv/shop/compose.prod.yml"),
        container("shop", "db", false, "/srv/shop", "/srv/shop/compose.yml,/srv/shop/compose.prod.yml"),
        container("shop", "web", true, "/srv/shop", "/srv/shop/compose.yml,/srv/shop/compose.prod.yml"),
        ContainerSummary::default(),
    ];
    let p = projects_from(&list);
    assert_eq!(p.len(), 1, "a container without labels is not a project");
    assert_eq!(p[0].name, "shop");
    assert_eq!(p[0].working_dir.as_deref(), Some("/srv/shop"));
    assert_eq!(p[0].config_files, vec!["/srv/shop/compose.yml", "/srv/shop/compose.prod.yml"]);
    assert_eq!(p[0].services, vec!["db", "web"]);
    assert_eq!((p[0].running, p[0].total), (2, 3));
}

#[test]
fn compose_command_names_the_project_its_dir_and_files() {
    let p = Project {
        name: "my app".into(),
        working_dir: Some("/srv/my app".into()),
        config_files: vec!["/srv/my app/compose.yml".into()],
        services: vec![],
        running: 0,
        total: 0,
    };
    assert_eq!(
        command("docker", &p, ComposeAction::Up),
        "docker compose --project-name 'my app' --project-directory '/srv/my app' -f '/srv/my app/compose.yml' up -d"
    );
    // down never removes volumes: that deletes data.
    let down = command("podman", &p, ComposeAction::Down);
    assert!(down.ends_with(" down") && !down.contains("-v"), "{down}");
}

#[test]
fn a_hostile_label_stays_one_argument() {
    let p = Project {
        name: "x; rm -rf ~".into(),
        working_dir: Some("$(reboot)".into()),
        config_files: vec!["`id`".into()],
        services: vec![],
        running: 0,
        total: 0,
    };
    let cmd = command("docker", &p, ComposeAction::Restart);
    assert!(cmd.contains("'x; rm -rf ~'") && cmd.contains("'$(reboot)'") && cmd.contains("'`id`'"), "{cmd}");
}

#[test]
fn container_rows_read_names_ports_and_compose() {
    let mut c = container("shop", "web", true, "/srv/shop", "/srv/shop/compose.yml");
    c.id = Some("abc".into());
    c.names = Some(vec!["/shop-web-1".into()]);
    c.ports = Some(vec![bollard::models::PortSummary {
        ip: Some("0.0.0.0".into()),
        private_port: 80,
        public_port: Some(8080),
        typ: Some(bollard::models::PortSummaryTypeEnum::TCP),
    }]);
    let r = container_row(c);
    assert_eq!(r.name, "shop-web-1");
    assert_eq!(r.ports, vec!["0.0.0.0:8080->80/tcp"]);
    assert_eq!((r.project.as_deref(), r.service.as_deref()), (Some("shop"), Some("web")));
    assert_eq!(r.state, "running");
}

#[test]
fn a_failed_command_reports_its_own_words() {
    let o = Output { code: Some(1), stdout: String::new(), stderr: "permission denied while trying to connect\n".into() };
    assert_eq!(o.failure("docker"), "docker failed: permission denied while trying to connect");
    let silent = Output { code: Some(127), ..Default::default() };
    assert_eq!(silent.failure("docker"), "docker failed (exit 127)");
}
