//! Turso Platform API client for creating databases and tokens.

use serde::{Deserialize, Serialize};

use crate::vault::error::VaultError;
use crate::vault::types::TursoDbInfo;

const TURSO_API_BASE: &str = "https://api.turso.tech/v1";

/// Create a new database in Turso.
pub async fn create_database(
    org: &str,
    api_token: &str,
    db_name: &str,
    group: &str,
) -> Result<TursoDbInfo, VaultError> {
    let client = crate::http::client();
    let url = format!("{}/organizations/{}/databases", TURSO_API_BASE, org);

    #[derive(Serialize)]
    struct CreateDbRequest<'a> {
        name: &'a str,
        group: &'a str,
    }

    #[derive(Deserialize)]
    struct CreateDbResponse {
        database: DatabaseInfo,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct DatabaseInfo {
        db_id: String,
        hostname: String,
        name: String,
    }

    let response = client
        .post(&url)
        .bearer_auth(api_token)
        .json(&CreateDbRequest { name: db_name, group })
        .send()
        .await
        .map_err(|e| VaultError::SyncError(format!("Failed to create Turso database: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(VaultError::SyncError(explain(status, &body, org)));
    }

    let result: CreateDbResponse = response
        .json()
        .await
        .map_err(|e| VaultError::SyncError(format!("Failed to parse Turso response: {}", e)))?;

    Ok(TursoDbInfo {
        db_id: result.database.db_id,
        hostname: result.database.hostname,
        name: result.database.name,
    })
}

/// Create an auth token for a Turso database.
pub async fn create_database_token(
    org: &str,
    api_token: &str,
    db_name: &str,
) -> Result<String, VaultError> {
    let client = crate::http::client();
    let url = format!(
        "{}/organizations/{}/databases/{}/auth/tokens",
        TURSO_API_BASE, org, db_name
    );

    #[derive(Deserialize)]
    struct TokenResponse {
        jwt: String,
    }

    let response = client
        .post(&url)
        .bearer_auth(api_token)
        .send()
        .await
        .map_err(|e| VaultError::SyncError(format!("Failed to create Turso token: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(VaultError::SyncError(explain(status, &body, org)));
    }

    let result: TokenResponse = response
        .json()
        .await
        .map_err(|e| VaultError::SyncError(format!("Failed to parse Turso token response: {}", e)))?;

    Ok(result.jwt)
}

/// What to do about the group a new database goes into.
#[derive(Debug, PartialEq, Eq)]
pub enum GroupChoice {
    /// It exists: use it.
    Use(String),
    /// The account has no group by that name: create it.
    Create(String),
}

/// Every Turso database belongs to a group, and a new account has none
/// until one is made (the dashboard makes one with the first database).
/// The wanted group is used when it exists. Left at "default" on an account
/// that has another group, that one is used: the free plan allows few
/// groups. Otherwise the wanted group is created.
pub fn choose_group(existing: &[String], wanted: &str) -> GroupChoice {
    if existing.iter().any(|g| g == wanted) {
        GroupChoice::Use(wanted.to_string())
    } else if wanted == "default" && !existing.is_empty() {
        GroupChoice::Use(existing[0].clone())
    } else {
        GroupChoice::Create(wanted.to_string())
    }
}

/// The names of the organization's groups.
pub async fn list_groups(org: &str, api_token: &str) -> Result<Vec<String>, VaultError> {
    #[derive(Deserialize)]
    struct Group {
        name: String,
    }
    #[derive(Deserialize)]
    struct Groups {
        #[serde(default)]
        groups: Vec<Group>,
    }
    let response = crate::http::client()
        .get(format!("{}/organizations/{}/groups", TURSO_API_BASE, org))
        .bearer_auth(api_token)
        .send()
        .await
        .map_err(|e| VaultError::SyncError(format!("Could not reach Turso: {}", e)))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(VaultError::SyncError(explain(status, &body, org)));
    }
    let groups: Groups = response.json().await.map_err(|e| VaultError::SyncError(format!("Failed to parse Turso response: {}", e)))?;
    Ok(groups.groups.into_iter().map(|g| g.name).collect())
}

/// Creates a group at the location closest to this computer.
pub async fn create_group(org: &str, api_token: &str, name: &str) -> Result<(), VaultError> {
    #[derive(Deserialize)]
    struct Closest {
        server: String,
    }
    let client = crate::http::client();
    let location = match client.get("https://region.turso.io").send().await {
        Ok(r) => r.json::<Closest>().await.map(|c| c.server).ok(),
        Err(_) => None,
    }
    .ok_or_else(|| VaultError::SyncError("Could not find the nearest Turso location for a new group".into()))?;
    let response = client
        .post(format!("{}/organizations/{}/groups", TURSO_API_BASE, org))
        .bearer_auth(api_token)
        .json(&serde_json::json!({ "name": name, "location": location }))
        .send()
        .await
        .map_err(|e| VaultError::SyncError(format!("Could not reach Turso: {}", e)))?;
    let status = response.status();
    // Made meanwhile by someone else is as good.
    if status.is_success() || status == reqwest::StatusCode::CONFLICT {
        tracing::info!("Turso: group {name} ready in {location}");
        return Ok(());
    }
    let body = response.text().await.unwrap_or_default();
    Err(VaultError::SyncError(format!("Turso could not create the group \"{name}\": {}", explain(status, &body, org))))
}

/// Turso's answer in words a person can act on.
fn explain(status: reqwest::StatusCode, body: &str, org: &str) -> String {
    match status.as_u16() {
        401 | 403 => format!(
            "Turso refused the API token ({status}). It must be a Platform API token (turso auth api-tokens mint, or Settings, API Tokens in the dashboard), not a database token. {body}"
        ),
        404 => format!(
            "Turso does not know the organization \"{org}\" ({status}). Use the organization's slug as `turso org list` shows it, not its display name. {body}"
        ),
        _ => format!("Turso API error ({status}): {body}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_is_found_or_made() {
        let g = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(choose_group(&g(&["default"]), "default"), GroupChoice::Use("default".into()));
        assert_eq!(choose_group(&g(&["reach"]), "default"), GroupChoice::Use("reach".into()));
        assert_eq!(choose_group(&g(&[]), "default"), GroupChoice::Create("default".into()));
        assert_eq!(choose_group(&g(&["a"]), "team"), GroupChoice::Create("team".into()));
        assert_eq!(choose_group(&g(&["a", "team"]), "team"), GroupChoice::Use("team".into()));
    }
}
