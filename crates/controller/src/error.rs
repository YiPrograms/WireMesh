use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid request: {0}")]
    Validation(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("internal server error")]
    Internal(#[from] anyhow::Error),
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, public_message) = match &self {
            Self::Unauthorized(message) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", message.clone())
            }
            Self::NotFound(message) => (StatusCode::NOT_FOUND, "not_found", message.clone()),
            Self::Conflict(message) => (StatusCode::CONFLICT, "conflict", message.clone()),
            Self::Validation(message) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_request",
                message.clone(),
            ),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, "forbidden", message.clone()),
            Self::Database(error) => {
                tracing::error!(error = %error, "database request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "database operation failed".into(),
                )
            }
            Self::Internal(error) => {
                tracing::error!(error = %error, "internal request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error".into(),
                )
            }
        };
        (
            status,
            Json(ErrorBody {
                code,
                message: public_message,
            }),
        )
            .into_response()
    }
}

impl From<wiremesh_domain::IdentityError> for ApiError {
    fn from(value: wiremesh_domain::IdentityError) -> Self {
        Self::Validation(value.to_string())
    }
}

impl From<wiremesh_domain::NetworkError> for ApiError {
    fn from(value: wiremesh_domain::NetworkError) -> Self {
        Self::Validation(value.to_string())
    }
}

impl From<wiremesh_domain::ConfigError> for ApiError {
    fn from(value: wiremesh_domain::ConfigError) -> Self {
        Self::Validation(value.to_string())
    }
}
