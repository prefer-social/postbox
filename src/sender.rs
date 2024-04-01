use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use sparrow::utils::get_current_time_in_rfc_1123;
use spin_sdk::http::{
    self, IncomingResponse, IntoResponse, Method, Params, Request, RequestBuilder, Response,
};
use spin_sdk::sqlite::Value as SV;
use tracing::{debug, info};
use url::Url;
use uuid::Uuid;

pub async fn post_inbox(message_str: &str) -> Result<u16> {
    let message: Value = serde_json::from_str(message_str)
        .expect("Message parse error: body should be proper json string.");

    debug!(message_str);

    let me = message.get("actor").unwrap().as_str().unwrap();
    let my_actor = Url::parse(me).unwrap();
    let user = my_actor
        .path_segments()
        .map(|c| c.collect::<Vec<_>>())
        .unwrap()
        .last()
        .unwrap()
        .clone();

    let recipient = "https://mas.to/users/seungjin";
    let recipient_actor = Url::parse(&recipient).unwrap();
    let recipient_server: &str = recipient_actor.host_str().unwrap();
    let recipient_inbox = "https://mas.to/users/seungjin/inbox";

    let private_key_pem = get_my_privekey(user).await.unwrap();
    let date = get_current_time_in_rfc_1123().await;
    let content_type = "application/activity+json".to_string();

    debug!("me -> {me}");
    debug!("my_actor -> {my_actor}");
    debug!("recipient_actor -> {recipient_actor}");
    debug!("recipient_server -> {recipient_server}");
    debug!("user -> {user}");
    debug!("private_key_pem -> {private_key_pem}");
    debug!("date -> {date}");
    debug!("content_type -> {content_type}");

    // TODO: This should be created from activity_stream crate not from string literal.

    debug!("request_body -> {message_str}");

    let mut hasher = Sha256::new();
    hasher.update(message_str.to_string());
    let digest = format!(
        "SHA-256={}",
        general_purpose::STANDARD.encode(hasher.finalize())
    );
    debug!("digest --> {digest}");

    let hostname = recipient_server.to_string();
    // FIXME: This should be get from actor info
    let inbox_path = format!("{}/inbox", recipient_actor.path());
    let signature_string = format!(
        "(request-target): post {}\nhost: {}\ndate: {}\ndigest: {}\ncontent-type: {}",
        inbox_path, hostname, date, digest, content_type
    );
    debug!("signature_string --> \n{signature_string}");

    // The signature string is constructed using the values of the HTTP headers defined in headers, joined by newlines. Typically, you will want to include the request target, as well as the host and the date. Mastodon assumes Date: header if none are provided. For the above GET request, to generate a Signature: with headers="(request-target) host date"
    // https://github.com/RustCrypto/RSA/issues/341
    let private_key =
        RsaPrivateKey::from_pkcs8_pem(&private_key_pem).expect("RsaPrivateKey creation failed");
    let signing_key: SigningKey<Sha256> = SigningKey::new(private_key);
    let signature =
        <SigningKey<Sha256> as Signer<Signature>>::sign(&signing_key, signature_string.as_bytes());
    let encoded_signature = general_purpose::STANDARD.encode(signature.to_bytes().as_ref());

    let sig_header = format!(
        r#"keyId="https://ap.dev.seungjin.net/users/seungjin#main-key",algorithm="rsa-sha256",headers="(request-target) host date digest content-type",signature="{}""#,
        encoded_signature
    );

    debug!(sig_header);

    // FIXME: Need to get INBOX url from actor request.

    let request = RequestBuilder::new(Method::Post, format!("{recipient_actor}/inbox")) // TODO: recipient uri should get from actor.
        .header("Date", date)
        .header("Signature", sig_header)
        .header("Digest", digest)
        .header("Content-Type", &content_type)
        .header("Accept", &content_type)
        .body(message_str.to_string())
        .build();
    let response: IncomingResponse = http::send(request).await?;
    let status = response.status();

    let body = String::from_utf8(response.into_body().await.unwrap()).unwrap();
    debug!("status --> {status}");
    debug!("response body -->\n{body}");

    Ok(status)
}

async fn get_my_privekey(name: &str) -> Result<String> {
    let qr = sparrow::db::Connection::builder().await.execute(
    "SELECT privateKey FROM signing_key JOIN user ON user.id = signing_key.userId WHERE user.name = ?", 
    &[SV::Text(name.to_string())]).await;
    let private_key = qr.rows().next().unwrap().get::<&str>("privateKey").unwrap();
    Ok(private_key.to_string())
}
