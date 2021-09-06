use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Debug)]
pub enum ObfuscatorType {
    Mock,
    Custom,
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Debug)]
pub enum ObfuscatorConfig {
    Mock,
    Custom {
        address: SocketAddr,
        remote_endpoint: SocketAddr,
    },
}
