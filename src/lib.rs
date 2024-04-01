use anyhow::Result;
use bytes::Bytes;
use serde_json::Value;
use sparrow::postbox::Envelop;
use spin_sdk::redis_component;
use std::str::from_utf8;
use tracing::debug;
use tracing_subscriber::{filter::EnvFilter, FmtSubscriber};

pub mod postman;

/// A simple Spin Redis component.
#[redis_component]
async fn on_message(e: Bytes) -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_env("APP_LOG_LEVEL"))
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    debug!("<---------- POSTMAN --------->");

    let envelop: Envelop<Value> = serde_json::from_str(from_utf8(&e).unwrap()).unwrap();

    let address = envelop.address.as_str();
    let letter = envelop.letter;

    debug!(address);
    debug!("{letter:?}");

    let a = postman::deliver(address, letter).await?;

    debug!(a);

    Ok(())
}
