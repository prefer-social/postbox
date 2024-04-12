use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer;
use rsa::RsaPrivateKey;
use serde_json::Value;
use sparrow::utils::clean_last_slash_from_url;
use sparrow::utils::get_current_time_in_rfc_1123;
use spin_sdk::http::{self, IncomingResponse, Method, RequestBuilder};
use url::Url;

use sparrow::utils::get_inbox_from_actor;
use sparrow::utils::get_privatekey_with_actor_url;

pub async fn deliver(actor: &str, letter: Value) -> Result<u16> {
    let me = letter.get("actor").unwrap().as_str().unwrap();

    let recipient_actor = Url::parse(&actor).unwrap();
    let recipient_server: &str = recipient_actor.host_str().unwrap();
    let recipient_inbox =
        get_inbox_from_actor(actor.to_string()).await.unwrap();

    let private_key_pem =
        get_privatekey_with_actor_url(me.to_string()).await.unwrap();
    let date = get_current_time_in_rfc_1123().await;
    let content_type = "application/activity+json".to_string();

    tracing::debug!("me -> {me}");
    tracing::debug!("recipient_actor -> {recipient_actor}");
    tracing::debug!("recipient_server -> {recipient_server}");
    tracing::debug!("date -> {date}");
    tracing::debug!("content_type -> {content_type}");

    // TODO: This should be created from activity_stream crate not from string literal.

    tracing::debug!("request_body -> {letter}");

    let mut hasher = Sha256::new();
    hasher.update(letter.to_string());
    let digest = format!(
        "SHA-256={}",
        general_purpose::STANDARD.encode(hasher.finalize())
    );
    tracing::debug!("digest --> {digest}");

    let hostname = recipient_server.to_string();
    // FIXME: This should be get from actor info
    let inbox_path = format!("{}/inbox", recipient_actor.path());
    let signature_string = format!(
        "(request-target): post {}\nhost: {}\ndate: {}\ndigest: {}\ncontent-type: {}",
        inbox_path, hostname, date, digest, content_type
    );
    tracing::debug!("signature_string --> \n{signature_string}");

    // The signature string is constructed using the values of the HTTP headers defined in headers, joined by newlines. Typically, you will want to include the request target, as well as the host and the date. Mastodon assumes Date: header if none are provided. For the above GET request, to generate a Signature: with headers="(request-target) host date"
    // https://github.com/RustCrypto/RSA/issues/341
    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem)
        .expect("RsaPrivateKey creation failed");
    let signing_key: SigningKey<Sha256> = SigningKey::new(private_key);
    let signature = <SigningKey<Sha256> as Signer<Signature>>::sign(
        &signing_key,
        signature_string.as_bytes(),
    );
    let encoded_signature =
        general_purpose::STANDARD.encode(signature.to_bytes().as_ref());

    let sig_header = format!(
        r#"keyId="{}#main-key",algorithm="rsa-sha256",headers="(request-target) host date digest content-type",signature="{}""#,
        me, encoded_signature
    );

    tracing::debug!(sig_header);

    let request = RequestBuilder::new(Method::Post, recipient_inbox) // TODO: recipient uri should get from actor.
        .header("Date", date)
        .header("Signature", sig_header)
        .header("Digest", digest)
        .header("Content-Type", &content_type)
        .header("Accept", &content_type)
        .body(letter.to_string())
        .build();
    let response: IncomingResponse = http::send(request).await?;
    let status = response.status();

    let body = String::from_utf8(response.into_body().await.unwrap()).unwrap();
    tracing::debug!("status --> {status}");
    tracing::debug!("response body -->\n{body}");

    Ok(status)
}
