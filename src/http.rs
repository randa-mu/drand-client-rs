use crate::{Transport, TransportError};
use reqwest::blocking::Client;
use reqwest::StatusCode;

pub struct HttpTransport {
    pub client: Client,
}

impl Transport for HttpTransport {
    fn fetch(&self, url: &str) -> Result<String, TransportError> {
        let res = self
            .client
            .get(url)
            .send()
            .map_err(|_| TransportError::Unexpected)?;

        match res.status() {
            StatusCode::OK => res.text().map_err(|_| TransportError::Unexpected),

            StatusCode::NOT_FOUND => Err(TransportError::NotFound),

            _ => Err(TransportError::Unexpected),
        }
    }
}

pub fn new_http_transport() -> HttpTransport {
    HttpTransport {
        client: Client::new(),
    }
}
