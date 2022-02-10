use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Debug)]
pub enum ObfuscatorType {
    Udp2Tcp,
    Mock,
    Custom,
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Debug)]
pub enum ObfuscatorConfig {
    Udp2Tcp,
    Mock,
    Custom {
        address: SocketAddr,
        remote_endpoint: SocketAddr,
    },
}
