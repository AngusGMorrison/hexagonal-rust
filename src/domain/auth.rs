pub mod models;

pub trait Service {
    fn register(req: &models::RegistrationRequest) -> Result<(), Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unhandleable error: {source}")]
    Unknown { source: anyhow::Error },
}
