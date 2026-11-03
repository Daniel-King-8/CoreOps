use std::io::Write;

use base64::Engine as _;
use k8s_openapi::api::core::v1::{
    ContainerState, ContainerStateRunning, ContainerStateTerminated, ContainerStateWaiting, ContainerStatus, Pod, PodSpec, PodStatus,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

use super::helm::{command, decode, HelmAction};
use super::*;

fn status(name: &str, ready: bool, state: ContainerState, restarts: i32) -> ContainerStatus {
    ContainerStatus { name: name.into(), ready, state: Some(state), restart_count: restarts, ..Default::default() }
}

fn pod(phase: &str, containers: Vec<ContainerStatus>) -> Pod {
    Pod {
        spec: Some(PodSpec {
            containers: containers.iter().map(|c| k8s_openapi::api::core::v1::Container { name: c.name.clone(), ..Default::default() }).collect(),
            ..Default::default()
        }),
        status: Some(PodStatus { phase: Some(phase.into()), container_statuses: Some(containers), ..Default::default() }),
        ..Default::default()
    }
}

fn running() -> ContainerState {
    ContainerState { running: Some(ContainerStateRunning::default()), ..Default::default() }
}

fn waiting(reason: &str) -> ContainerState {
    ContainerState { waiting: Some(ContainerStateWaiting { reason: Some(reason.into()), ..Default::default() }), ..Default::default() }
}

/// What kubectl prints is what the user sees: the reason, not "Running".
#[test]
fn pod_status_reads_like_kubectl() {
    assert_eq!(pod_status(&pod("Running", vec![status("app", true, running(), 0)])), "Running");
    assert_eq!(pod_status(&pod("Running", vec![status("app", false, waiting("CrashLoopBackOff"), 14)])), "CrashLoopBackOff");
    assert_eq!(pod_status(&pod("Pending", vec![status("app", false, waiting("ImagePullBackOff"), 0)])), "ImagePullBackOff");
    let oom = ContainerState {
        terminated: Some(ContainerStateTerminated { exit_code: 137, reason: Some("OOMKilled".into()), ..Default::default() }),
        ..Default::default()
    };
    assert_eq!(pod_status(&pod("Running", vec![status("app", false, oom, 3)])), "OOMKilled");
    let mut gone = pod("Running", vec![status("app", true, running(), 0)]);
    gone.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
    assert_eq!(pod_status(&gone), "Terminating");
}

#[test]
fn pod_row_counts_ready_and_restarts() {
    let r = pod_row(pod("Running", vec![status("a", true, running(), 2), status("b", false, waiting("CrashLoopBackOff"), 5)]));
    assert_eq!(r.ready, "1/2");
    assert_eq!(r.restarts, 7);
    assert_eq!(r.status, "CrashLoopBackOff");
}

const KUBECONFIG: &str = r#"
apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: https://10.0.0.5:6443
- name: dev-cluster
  cluster:
    server: https://k8s.dev.example.com
contexts:
- name: prod
  context: { cluster: prod-cluster, user: admin, namespace: shop }
- name: dev
  context: { cluster: dev-cluster, user: dev }
users:
- name: admin
  user: { token: x }
- name: dev
  user: { token: y }
"#;

#[test]
fn contexts_list_server_namespace_and_current() {
    let (list, current) = contexts(KUBECONFIG).unwrap();
    assert_eq!(current.as_deref(), Some("prod"));
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].server, "https://10.0.0.5:6443");
    assert_eq!(list[0].namespace.as_deref(), Some("shop"));
    assert!(contexts("not: [a kubeconfig").is_err());
}

#[test]
fn server_addresses_for_the_tunnel() {
    assert_eq!(server_addr("https://10.0.0.5:6443").unwrap(), ("10.0.0.5".into(), 6443));
    assert_eq!(server_addr("https://k8s.dev.example.com").unwrap(), ("k8s.dev.example.com".into(), 443));
    assert_eq!(server_addr("https://[fd00::1]:6443").unwrap(), ("fd00::1".into(), 6443));
}

fn helm_stored(json: &str) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(json.as_bytes()).unwrap();
    base64::engine::general_purpose::STANDARD.encode(gz.finish().unwrap()).into_bytes()
}

#[test]
fn helm_release_decodes_from_its_storage_format() {
    let v = decode(&helm_stored(r#"{"name":"web","version":3,"info":{"status":"deployed"}}"#)).unwrap();
    assert_eq!(v["name"], "web");
    assert_eq!(v["version"], 3);
    assert!(decode(b"!!not base64!!").is_err());
}

#[test]
fn helm_commands_are_quoted_and_checked() {
    assert_eq!(
        command(HelmAction::Rollback, "shop", "web", Some(2), Some("prod")).unwrap(),
        "helm rollback web 2 --wait --namespace shop --kube-context prod"
    );
    assert!(command(HelmAction::Rollback, "shop", "web", None, None).is_err());
    assert!(command(HelmAction::Rollback, "shop", "web", Some(0), None).is_err());
    let hostile = command(HelmAction::Uninstall, "x; reboot", "$(id)", None, None).unwrap();
    assert!(hostile.contains("'$(id)'") && hostile.contains("'x; reboot'"), "{hostile}");
}

#[test]
fn only_replica_kinds_scale_and_only_controllers_restart() {
    assert!(Kind::Deployment.scalable() && Kind::StatefulSet.scalable());
    assert!(!Kind::DaemonSet.scalable() && !Kind::Pod.scalable());
    assert!(Kind::DaemonSet.restartable() && !Kind::Pod.restartable() && !Kind::Service.restartable());
}

/// The kubeconfig reaches helm through a private temp file that is removed
/// however helm ends; checked by running the wrapper in a real shell. The
/// wrapper runs on the SSH server (Linux, macOS), never on a phone, so it is
/// checked where it runs.
#[cfg(all(unix, not(target_os = "android")))]
#[test]
fn helm_kubeconfig_file_is_private_and_removed() {
    let mark = std::env::temp_dir().join(format!("reach-kc-path-{}", std::process::id()));
    use super::helm::with_stdin_kubeconfig;
    use std::io::Write;
    // Stand-in for helm: report the file's mode (GNU stat, or BSD stat on
    // macOS) and content, then fail.
    let fake = r#"sh -c '{ stat -c %a "$2" 2>/dev/null || stat -f %Lp "$2"; }; cat "$2"; echo "$2" > "$REACH_KC_MARK"; exit 3' x"#;
    let cmd = with_stdin_kubeconfig(fake);
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .env("REACH_KC_MARK", &mark)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"apiVersion: v1\n").unwrap();
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(3), "helm's own exit code comes back");
    assert!(text.starts_with("600\n"), "the file is owner-only: {text}");
    assert!(text.contains("apiVersion: v1"), "{text}");
    let path = std::fs::read_to_string(&mark).unwrap();
    let _ = std::fs::remove_file(&mark);
    assert!(!std::path::Path::new(path.trim()).exists(), "the kubeconfig file was left behind");
}

/// A cluster that does not answer is named by its own address, in words a
/// user can act on, not the client's "ServiceError: client error (Connect)".
#[tokio::test]
async fn an_unreachable_cluster_says_where() {
    // As the app does at start (lib.rs): rustls needs a provider chosen.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let yaml = "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster: {server: 'https://127.0.0.1:1', insecure-skip-tls-verify: true}\ncontexts:\n- name: c\n  context: {cluster: c, user: u}\nusers:\n- name: u\n  user: {token: x}\n";
    let err = connect(yaml, Some("c"), None).await.err().expect("nothing listens on port 1");
    assert!(err.starts_with("Could not reach the API server at https://127.0.0.1:1"), "{err}");
}
