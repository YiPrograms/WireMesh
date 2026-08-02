use std::collections::{BTreeSet, HashMap};

use chrono::Utc;
use csv::{ReaderBuilder, StringRecord, Trim};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;

use crate::{
    desired,
    error::ApiError,
    models::{
        ImportFormat, ImportUserRowResponse, ImportUsersPreviewResponse, ImportUsersRequest,
    },
    service,
};

const MAX_IMPORT_BYTES: usize = 2 * 1024 * 1024;
const MAX_IMPORT_ROWS: usize = 10_000;

#[derive(Debug, Clone)]
struct ParsedRow {
    row: usize,
    email: String,
    name: String,
    title: String,
    groups: Vec<String>,
    errors: Vec<String>,
}

pub async fn preview(
    pool: &SqlitePool,
    request: ImportUsersRequest,
) -> Result<ImportUsersPreviewResponse, ApiError> {
    let rows = parse(request)?;
    preview_rows(pool, rows).await
}

pub async fn apply(
    pool: &SqlitePool,
    actor: Uuid,
    request: ImportUsersRequest,
) -> Result<ImportUsersPreviewResponse, ApiError> {
    let rows = parse(request)?;
    let preview = preview_rows(pool, rows.clone()).await?;
    if !preview.valid {
        return Err(ApiError::Validation(
            "import has validation errors; review the preview before applying".into(),
        ));
    }
    let timestamp = Utc::now().to_rfc3339();
    let mut transaction = pool.begin().await?;
    let mut affected_users = BTreeSet::new();
    for row in rows {
        let existing = sqlx::query("SELECT id,soft_deleted_at FROM users WHERE email=?")
            .bind(&row.email)
            .fetch_optional(&mut *transaction)
            .await?;
        let user_id = match existing {
            Some(existing) => {
                if existing.try_get::<Option<String>, _>("soft_deleted_at")?.is_some() {
                    return Err(ApiError::Conflict(format!(
                        "{} became soft-deleted after preview",
                        row.email
                    )));
                }
                let user_id = parse_uuid(&existing.try_get::<String, _>("id")?)?;
                let has_local: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM user_identities WHERE user_id=? AND kind='local'",
                )
                .bind(user_id.to_string())
                .fetch_one(&mut *transaction)
                .await?;
                if has_local == 0 {
                    sqlx::query(
                        "INSERT INTO user_identities(id,user_id,kind,external_id,current_email,created_at,updated_at)
                         VALUES(?,?,?,?,?,?,?)",
                    )
                    .bind(Uuid::now_v7().to_string())
                    .bind(user_id.to_string())
                    .bind("local")
                    .bind(&row.email)
                    .bind(&row.email)
                    .bind(&timestamp)
                    .bind(&timestamp)
                    .execute(&mut *transaction)
                    .await?;
                }
                user_id
            }
            None => {
                let user_id = Uuid::now_v7();
                sqlx::query(
                    "INSERT INTO users(id,email,name,title,creator_kind,created_at,updated_at)
                     VALUES(?,?,?,?,?,?,?)",
                )
                .bind(user_id.to_string())
                .bind(&row.email)
                .bind(&row.name)
                .bind(&row.title)
                .bind("local")
                .bind(&timestamp)
                .bind(&timestamp)
                .execute(&mut *transaction)
                .await?;
                sqlx::query(
                    "INSERT INTO user_identities(id,user_id,kind,external_id,current_email,created_at,updated_at)
                     VALUES(?,?,?,?,?,?,?)",
                )
                .bind(Uuid::now_v7().to_string())
                .bind(user_id.to_string())
                .bind("local")
                .bind(&row.email)
                .bind(&row.email)
                .bind(&timestamp)
                .bind(&timestamp)
                .execute(&mut *transaction)
                .await?;
                user_id
            }
        };
        affected_users.insert(user_id);
        for group in row.groups {
            let group_id = upsert_group(&mut transaction, &group).await?;
            sqlx::query(
                "INSERT INTO group_memberships(id,group_id,user_id,source_kind,source_id,active,updated_at)
                 VALUES(?,?,?,?,?,1,?)
                 ON CONFLICT(group_id,user_id,source_kind,source_id)
                 DO UPDATE SET active=1,updated_at=excluded.updated_at",
            )
            .bind(Uuid::now_v7().to_string())
            .bind(group_id.to_string())
            .bind(user_id.to_string())
            .bind("local")
            .bind("import")
            .bind(&timestamp)
            .execute(&mut *transaction)
            .await?;
        }
    }
    service::refresh_all_client_configs(&mut transaction).await?;
    desired::rebuild_all_gateways(&mut transaction, Vec::new()).await?;
    sqlx::query(
        "INSERT INTO audit_events(id,occurred_at,actor_user_id,actor_kind,action,object_kind,outcome,details_json)
         VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(&timestamp)
    .bind(actor.to_string())
    .bind("user")
    .bind("users.import")
    .bind("user")
    .bind("success")
    .bind(serde_json::json!({
        "rows": preview.rows.len(),
        "creates": preview.creates,
        "links": preview.links,
        "affected_users": affected_users.len(),
    }).to_string())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(preview)
}

async fn preview_rows(
    pool: &SqlitePool,
    rows: Vec<ParsedRow>,
) -> Result<ImportUsersPreviewResponse, ApiError> {
    let mut output = Vec::with_capacity(rows.len());
    let mut creates = 0;
    let mut links = 0;
    let mut errors = 0;
    for row in rows {
        let mut row_errors = row.errors;
        let existing = if row.email.is_empty() {
            None
        } else {
            sqlx::query("SELECT soft_deleted_at FROM users WHERE email=?")
                .bind(&row.email)
                .fetch_optional(pool)
                .await?
        };
        let action = if !row_errors.is_empty() {
            "error"
        } else if existing
            .as_ref()
            .is_some_and(|value| value.try_get::<Option<String>, _>("soft_deleted_at").ok().flatten().is_some())
        {
            row_errors.push("email belongs to a soft-deleted user; restore or purge it first".into());
            "error"
        } else if existing.is_some() {
            links += 1;
            "link"
        } else {
            creates += 1;
            "create"
        };
        if action == "error" {
            errors += 1;
        }
        output.push(ImportUserRowResponse {
            row: row.row,
            email: row.email,
            name: row.name,
            title: row.title,
            groups: row.groups,
            action: action.into(),
            errors: row_errors,
        });
    }
    Ok(ImportUsersPreviewResponse {
        valid: errors == 0 && !output.is_empty(),
        creates,
        links,
        errors,
        rows: output,
    })
}

fn parse(request: ImportUsersRequest) -> Result<Vec<ParsedRow>, ApiError> {
    if request.content.len() > MAX_IMPORT_BYTES {
        return Err(ApiError::Validation("import file exceeds 2 MiB".into()));
    }
    let delimiter = match request.format {
        ImportFormat::Csv => b',',
        ImportFormat::Tsv => b'\t',
    };
    let mut reader = ReaderBuilder::new()
        .delimiter(delimiter)
        .trim(Trim::All)
        .flexible(false)
        .from_reader(request.content.as_bytes());
    let headers = reader
        .headers()
        .map_err(|error| ApiError::Validation(format!("invalid import header: {error}")))?
        .clone();
    let indices = header_indices(&headers)?;
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for (index, result) in reader.records().enumerate() {
        if index >= MAX_IMPORT_ROWS {
            return Err(ApiError::Validation("import exceeds 10,000 rows".into()));
        }
        let record = result.map_err(|error| {
            ApiError::Validation(format!("invalid import row {}: {error}", index + 2))
        })?;
        let raw_email = value(&record, indices["email"]);
        let email = wiremesh_domain::normalize_email(raw_email).unwrap_or_default();
        let name = value(&record, indices["name"]).trim().to_owned();
        let title = indices.get("title").map_or("", |position| value(&record, *position)).trim().to_owned();
        let mut errors = Vec::new();
        if email.is_empty() {
            errors.push("email is invalid".into());
        } else if !seen.insert(email.clone()) {
            errors.push("email is duplicated in this import".into());
        }
        if name.is_empty() {
            errors.push("name is required".into());
        }
        let mut groups = BTreeSet::new();
        if let Some(position) = indices.get("groups") {
            for group in value(&record, *position).split(';').filter(|value| !value.trim().is_empty()) {
                match wiremesh_domain::normalize_group_name(group) {
                    Ok(group) => { groups.insert(group); }
                    Err(error) => errors.push(error.to_string()),
                }
            }
        }
        rows.push(ParsedRow {
            row: index + 2,
            email,
            name,
            title,
            groups: groups.into_iter().collect(),
            errors,
        });
    }
    Ok(rows)
}

fn header_indices(headers: &StringRecord) -> Result<HashMap<String, usize>, ApiError> {
    let mut result = HashMap::new();
    for (index, value) in headers.iter().enumerate() {
        let normalized = value.trim().to_ascii_lowercase();
        if !matches!(normalized.as_str(), "name" | "email" | "title" | "groups") {
            return Err(ApiError::Validation(format!("unsupported import column {value}")));
        }
        if result.insert(normalized.clone(), index).is_some() {
            return Err(ApiError::Validation(format!("duplicate import column {value}")));
        }
    }
    for required in ["name", "email"] {
        if !result.contains_key(required) {
            return Err(ApiError::Validation(format!("missing required {required} column")));
        }
    }
    Ok(result)
}

fn value(record: &StringRecord, index: usize) -> &str {
    record.get(index).unwrap_or_default()
}

async fn upsert_group(
    transaction: &mut Transaction<'_, Sqlite>,
    name: &str,
) -> Result<Uuid, ApiError> {
    if let Some(id) = sqlx::query_scalar::<_, String>("SELECT id FROM groups WHERE normalized_name=?")
        .bind(name)
        .fetch_optional(&mut **transaction)
        .await?
    {
        return parse_uuid(&id);
    }
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO groups(id,normalized_name,display_name,created_at) VALUES(?,?,?,?)")
        .bind(id.to_string())
        .bind(name)
        .bind(name)
        .bind(Utc::now().to_rfc3339())
        .execute(&mut **transaction)
        .await?;
    Ok(id)
}

fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
    value.parse().map_err(|error| ApiError::Internal(anyhow::anyhow!("invalid user UUID: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_parser_normalizes_and_rejects_duplicate_rows() {
        let rows = parse(ImportUsersRequest {
            format: ImportFormat::Csv,
            content: "name,email,title,groups\nAlice, ALICE@Example.COM ,Ops,Staff; VPN Users\nOther,alice@example.com,,\n".into(),
        })
        .unwrap();
        assert_eq!(rows[0].email, "alice@example.com");
        assert_eq!(rows[0].groups, vec!["staff", "vpn users"]);
        assert!(rows[1].errors.iter().any(|error| error.contains("duplicated")));
    }
}
