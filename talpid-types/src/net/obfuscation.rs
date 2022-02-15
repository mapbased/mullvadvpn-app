use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

// TODO: Why is this even defined here??
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Debug)]
pub enum ObfuscatorType {
    Udp2Tcp,
    Mock,
    Custom,
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Debug)]
pub enum ObfuscatorConfig {
    Udp2Tcp {
        endpoint: SocketAddr,
    },
    // TODO: Remove this
    Mock,
    // TODO: Remove this
    Custom {
        address: SocketAddr,
        remote_endpoint: SocketAddr,
    },
}
