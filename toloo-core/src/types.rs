use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The only top-level protocol structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub d: DatumBody,
    pub p: String,
}

/// Signed datum inside an envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DatumBody {
    pub n: String,
    pub v: String,
    pub t: String,
    pub ts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Box<Envelope>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tc: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(flatten, default)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct LocalNode {
    pub sig: Keypair,
    pub enc: Keypair,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct LocalRoom {
    pub sig: Keypair,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    pub pub_key: String,
    pub priv_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EndpointDescriptor {
    pub proto: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct: Option<bool>,
    #[serde(flatten, default)]
    pub extra: HashMap<String, Value>,
}
