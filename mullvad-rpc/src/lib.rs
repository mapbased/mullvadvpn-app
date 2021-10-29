#![deny(rust_2018_idioms)]

use chrono::{offset::Utc, DateTime};
#[cfg(target_os = "android")]
use futures::channel::mpsc;
use hyper::Method;
use mullvad_types::{
    account::{AccountToken, VoucherSubmission},
    device::{Device, DeviceId, DeviceName},
    version::AppVersion,
};
use std::{
    collections::BTreeMap,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
};
use talpid_types::{net::wireguard, ErrorExt};

pub mod availability;
use availability::{ApiAvailability, ApiAvailabilityHandle};
pub mod rest;

mod abortable_stream;
mod https_client_with_sni;
mod tls_stream;
#[cfg(target_os = "android")]
pub use crate::https_client_with_sni::SocketBypassRequest;

mod address_cache;
mod relay_list;
pub use address_cache::{AddressCache, CurrentAddressChangeListener};
pub use hyper::StatusCode;
pub use relay_list::RelayListProxy;

/// Error code returned by the Mullvad API if the voucher has alreaby been used.
pub const VOUCHER_USED: &str = "VOUCHER_USED";

/// Error code returned by the Mullvad API if the voucher code is invalid.
pub const INVALID_VOUCHER: &str = "INVALID_VOUCHER";

/// Error code returned by the Mullvad API if the account token is invalid.
pub const INVALID_ACCOUNT: &str = "INVALID_ACCOUNT";

/// Error code returned by the Mullvad API if the account token is missing or invalid.
pub const INVALID_AUTH: &str = "INVALID_AUTH";

pub const MAX_DEVICES_REACHED: &str = "MAX_DEVICES_REACHED";
pub const PUBKEY_IN_USE: &str = "PUBKEY_IN_USE";

pub const API_IP_CACHE_FILENAME: &str = "api-ip-address.txt";

lazy_static::lazy_static! {
    static ref API: ApiEndpoint = ApiEndpoint::get();
}

/// A hostname and socketaddr to reach the Mullvad REST API over.
struct ApiEndpoint {
    host: String,
    addr: SocketAddr,
    disable_address_cache: bool,
}

impl ApiEndpoint {
    /// Returns the endpoint to connect to the API over.
    ///
    /// # Panics
    ///
    /// Panics if `MULLVAD_API_ADDR` has invalid contents or if only one of
    /// `MULLVAD_API_ADDR` or `MULLVAD_API_HOST` has been set but not the other.
    fn get() -> ApiEndpoint {
        const API_HOST_DEFAULT: &str = "api.mullvad.net";
        const API_IP_DEFAULT: IpAddr = IpAddr::V4(Ipv4Addr::new(193, 138, 218, 78));
        const API_PORT_DEFAULT: u16 = 443;

        fn read_var(key: &'static str) -> Option<String> {
            use std::env;
            match env::var(key) {
                Ok(v) => Some(v),
                Err(env::VarError::NotPresent) => None,
                Err(env::VarError::NotUnicode(_)) => panic!("{} does not contain valid UTF-8", key),
            }
        }

        let host_var = read_var("MULLVAD_API_HOST");
        let address_var = read_var("MULLVAD_API_ADDR");

        let mut api = ApiEndpoint {
            host: API_HOST_DEFAULT.to_owned(),
            addr: SocketAddr::new(API_IP_DEFAULT, API_PORT_DEFAULT),
            disable_address_cache: false,
        };

        if cfg!(feature = "api-override") {
            match (host_var, address_var) {
                (None, None) => (),
                (Some(_), None) => panic!("MULLVAD_API_HOST is set, but not MULLVAD_API_ADDR"),
                (None, Some(_)) => panic!("MULLVAD_API_ADDR is set, but not MULLVAD_API_HOST"),
                (Some(user_host), Some(user_addr)) => {
                    api.host = user_host;
                    api.addr = user_addr
                        .parse()
                        .expect("MULLVAD_API_ADDR is not a valid socketaddr");
                    api.disable_address_cache = true;
                    log::debug!("Overriding API. Using {} at {}", api.host, api.addr);
                }
            }
        } else {
            if host_var.is_some() || address_var.is_some() {
                log::warn!(
                    "MULLVAD_API_HOST and MULLVAD_API_ADDR are ignored in production builds"
                );
            }
        }
        api
    }
}

/// A type that helps with the creation of RPC connections.
pub struct MullvadRpcRuntime {
    handle: tokio::runtime::Handle,
    pub address_cache: AddressCache,
    api_availability: availability::ApiAvailability,
    #[cfg(target_os = "android")]
    socket_bypass_tx: Option<mpsc::Sender<SocketBypassRequest>>,
}

#[derive(err_derive::Error, Debug)]
pub enum Error {
    #[error(display = "Failed to construct a rest client")]
    RestError(#[error(source)] rest::Error),

    #[error(display = "Failed to load address cache")]
    AddressCacheError(#[error(source)] address_cache::Error),

    #[error(display = "API availability check failed")]
    ApiCheckError(#[error(source)] availability::Error),
}

impl MullvadRpcRuntime {
    /// Create a new `MullvadRpcRuntime`.
    pub fn new(handle: tokio::runtime::Handle) -> Result<Self, Error> {
        Self::new_inner(
            handle,
            #[cfg(target_os = "android")]
            None,
        )
    }

    fn new_inner(
        handle: tokio::runtime::Handle,
        #[cfg(target_os = "android")] socket_bypass_tx: Option<mpsc::Sender<SocketBypassRequest>>,
    ) -> Result<Self, Error> {
        Ok(MullvadRpcRuntime {
            handle,
            address_cache: AddressCache::new(vec![API.addr], None)?,
            api_availability: ApiAvailability::new(availability::State::default()),
            #[cfg(target_os = "android")]
            socket_bypass_tx,
        })
    }

    /// Create a new `MullvadRpcRuntime` using the specified directories.
    /// Try to use the cache directory first, and fall back on the resource directory
    /// if it fails.
    pub async fn with_cache(
        resource_dir: Option<&Path>,
        cache_dir: &Path,
        write_changes: bool,
        #[cfg(target_os = "android")] socket_bypass_tx: Option<mpsc::Sender<SocketBypassRequest>>,
    ) -> Result<Self, Error> {
        let handle = tokio::runtime::Handle::current();
        if API.disable_address_cache {
            return Self::new_inner(
                handle,
                #[cfg(target_os = "android")]
                socket_bypass_tx,
            );
        }

        let cache_file = cache_dir.join(API_IP_CACHE_FILENAME);
        let write_file = if write_changes {
            Some(cache_file.clone().into_boxed_path())
        } else {
            None
        };

        let address_cache = match AddressCache::from_file(&cache_file, write_file.clone()).await {
            Ok(cache) => cache,
            Err(error) => {
                let cache_exists = cache_file.exists();
                if cache_exists {
                    log::error!(
                        "{}",
                        error.display_chain_with_msg(
                            "Failed to load cached API addresses. Falling back on bundled list"
                        )
                    );
                }

                // Initialize the cache directory cache using the resource directory
                match resource_dir {
                    Some(resource_dir) => {
                        let read_file = resource_dir.join(API_IP_CACHE_FILENAME);
                        let cache = AddressCache::from_file(&read_file, write_file).await?;
                        cache.randomize().await?;
                        cache
                    }
                    None => return Err(Error::AddressCacheError(error)),
                }
            }
        };

        Ok(MullvadRpcRuntime {
            handle,
            address_cache,
            api_availability: ApiAvailability::new(availability::State::default()),
            #[cfg(target_os = "android")]
            socket_bypass_tx,
        })
    }

    pub fn set_address_change_listener(
        &mut self,
        address_change_listener: impl Fn(SocketAddr) -> Result<(), ()> + Send + Sync + 'static,
    ) {
        self.address_cache
            .set_change_listener(Arc::new(Box::new(address_change_listener)));
    }

    /// Creates a new request service and returns a handle to it.
    fn new_request_service(&mut self, sni_hostname: Option<String>) -> rest::RequestServiceHandle {
        let service = rest::RequestService::new(
            self.handle.clone(),
            sni_hostname,
            self.api_availability.handle(),
            self.address_cache.clone(),
            #[cfg(target_os = "android")]
            self.socket_bypass_tx.clone(),
        );
        let handle = service.handle();
        self.handle.spawn(service.into_future());
        handle
    }

    /// Returns a request factory initialized to create requests for the master API
    pub fn mullvad_rest_handle(&mut self) -> rest::MullvadRestHandle {
        let service = self.new_request_service(Some(API.host.clone()));
        let factory =
            rest::RequestFactory::new(API.host.clone(), Box::new(self.address_cache.clone()), None);

        rest::MullvadRestHandle::new(
            service,
            factory,
            self.address_cache.clone(),
            self.availability_handle(),
        )
    }

    /// Returns a new request service handle
    pub fn rest_handle(&mut self) -> rest::RequestServiceHandle {
        self.new_request_service(None)
    }

    pub fn handle(&mut self) -> &mut tokio::runtime::Handle {
        &mut self.handle
    }

    pub fn availability_handle(&self) -> ApiAvailabilityHandle {
        self.api_availability.handle()
    }
}

#[derive(Clone)]
pub struct AccountsProxy {
    handle: rest::MullvadRestHandle,
}

#[derive(serde::Deserialize)]
struct AccountResponse {
    token: AccountToken,
    expiry: DateTime<Utc>,
}

impl AccountsProxy {
    pub fn new(handle: rest::MullvadRestHandle) -> Self {
        Self { handle }
    }

    pub fn get_expiry(
        &self,
        account: AccountToken,
    ) -> impl Future<Output = Result<DateTime<Utc>, rest::Error>> {
        let service = self.handle.service.clone();

        let response = rest::send_request(
            &self.handle.factory,
            service,
            "accounts/v1-alpha/accounts/me",
            Method::GET,
            Some(account),
            &[StatusCode::OK],
        );
        async move {
            let account: AccountResponse = rest::deserialize_body(response.await?).await?;
            Ok(account.expiry)
        }
    }

    pub fn create_account(&mut self) -> impl Future<Output = Result<AccountToken, rest::Error>> {
        let service = self.handle.service.clone();
        let response = rest::send_request(
            &self.handle.factory,
            service,
            "accounts/v1-alpha/accounts",
            Method::POST,
            None,
            &[StatusCode::CREATED],
        );

        async move {
            let account: AccountResponse = rest::deserialize_body(response.await?).await?;
            Ok(account.token)
        }
    }

    pub fn submit_voucher(
        &mut self,
        account_token: AccountToken,
        voucher_code: String,
    ) -> impl Future<Output = Result<VoucherSubmission, rest::Error>> {
        #[derive(serde::Serialize)]
        struct VoucherSubmission {
            voucher_code: String,
        }

        let service = self.handle.service.clone();
        let submission = VoucherSubmission { voucher_code };

        let response = rest::send_json_request(
            &self.handle.factory,
            service,
            "app/v1/submit-voucher",
            Method::POST,
            &submission,
            Some(account_token),
            &[StatusCode::OK],
        );

        async move { rest::deserialize_body(response.await?).await }
    }

    pub fn get_www_auth_token(
        &self,
        account: AccountToken,
    ) -> impl Future<Output = Result<String, rest::Error>> {
        #[derive(serde::Deserialize)]
        struct AuthTokenResponse {
            auth_token: String,
        }

        let service = self.handle.service.clone();
        let response = rest::send_request(
            &self.handle.factory,
            service,
            "app/v1/www-auth-token",
            Method::POST,
            Some(account),
            &[StatusCode::OK],
        );

        async move {
            let response: AuthTokenResponse = rest::deserialize_body(response.await?).await?;
            Ok(response.auth_token)
        }
    }
}

#[derive(Clone)]
pub struct DevicesProxy {
    handle: rest::MullvadRestHandle,
}

#[derive(serde::Deserialize)]
struct DeviceResponse {
    id: DeviceId,
    name: DeviceName,
    pubkey: wireguard::PublicKey,
    ipv4_address: ipnetwork::Ipv4Network,
    ipv6_address: ipnetwork::Ipv6Network,
}

impl DevicesProxy {
    pub fn new(handle: rest::MullvadRestHandle) -> Self {
        Self { handle }
    }

    pub fn create(
        &self,
        account: AccountToken,
        pubkey: wireguard::PublicKey,
    ) -> impl Future<Output = Result<(Device, mullvad_types::wireguard::AssociatedAddresses), rest::Error>>
    {
        #[derive(serde::Serialize)]
        struct DeviceSubmission {
            pubkey: wireguard::PublicKey,
            kind: String,
        }

        let submission = DeviceSubmission {
            pubkey,
            // TODO: constant
            kind: "App".to_string(),
        };

        let service = self.handle.service.clone();
        let response = rest::send_json_request(
            &self.handle.factory,
            service,
            // TODO: Configurable prefix. Lazy static?
            "accounts/v1-alpha/devices",
            Method::POST,
            &submission,
            Some(account),
            StatusCode::CREATED,
        );

        async move {
            let response: DeviceResponse = rest::deserialize_body(response.await?).await?;
            let DeviceResponse {
                id,
                name,
                pubkey,
                ipv4_address,
                ipv6_address,
                ..
            } = response;

            Ok((
                Device { id, name, pubkey },
                mullvad_types::wireguard::AssociatedAddresses {
                    ipv4_address,
                    ipv6_address,
                },
            ))
        }
    }

    pub fn get(
        &self,
        account: AccountToken,
        id: DeviceId,
    ) -> impl Future<Output = Result<Device, rest::Error>> {
        let service = self.handle.service.clone();
        let response = rest::send_request(
            &self.handle.factory,
            service,
            &format!(
                // TODO: Configurable prefix. Lazy static?
                "accounts/v1-alpha/devices/{}",
                id,
            ),
            Method::GET,
            Some(account),
            StatusCode::OK,
        );
        async move { rest::deserialize_body(response.await?).await }
    }

    pub fn list(
        &self,
        account: AccountToken,
    ) -> impl Future<Output = Result<Vec<Device>, rest::Error>> {
        let service = self.handle.service.clone();
        let response = rest::send_request(
            &self.handle.factory,
            service,
            // TODO: Configurable prefix. Lazy static?
            "accounts/v1-alpha/devices",
            Method::GET,
            Some(account),
            StatusCode::OK,
        );
        async move { rest::deserialize_body(response.await?).await }
    }

    pub fn remove(
        &self,
        account: AccountToken,
        id: DeviceId,
    ) -> impl Future<Output = Result<(), rest::Error>> {
        let service = self.handle.service.clone();
        let response = rest::send_request(
            &self.handle.factory,
            service,
            &format!(
                // TODO: Configurable prefix. Lazy static?
                "accounts/v1-alpha/devices/{}",
                id,
            ),
            Method::DELETE,
            Some(account),
            StatusCode::NO_CONTENT,
        );
        async move {
            response.await?;
            Ok(())
        }
    }

    pub fn replace_wg_key(
        &self,
        account: AccountToken,
        id: DeviceId,
        pubkey: wireguard::PublicKey,
    ) -> impl Future<Output = Result<mullvad_types::wireguard::AssociatedAddresses, rest::Error>>
    {
        #[derive(serde::Serialize)]
        struct RotateDevicePubkey {
            pubkey: wireguard::PublicKey,
        }
        let req_body = RotateDevicePubkey { pubkey };

        let service = self.handle.service.clone();
        let response = rest::send_json_request(
            &self.handle.factory,
            service,
            &format!(
                // TODO: Configurable prefix. Lazy static?
                "accounts/v1-alpha/devices/{}/pubkey",
                id,
            ),
            Method::PUT,
            &req_body,
            Some(account),
            StatusCode::OK,
        );

        async move {
            let updated_device: DeviceResponse = rest::deserialize_body(response.await?).await?;
            let DeviceResponse {
                ipv4_address,
                ipv6_address,
                ..
            } = updated_device;
            Ok(mullvad_types::wireguard::AssociatedAddresses {
                ipv4_address,
                ipv6_address,
            })
        }
    }
}

pub struct ProblemReportProxy {
    handle: rest::MullvadRestHandle,
}

impl ProblemReportProxy {
    pub fn new(handle: rest::MullvadRestHandle) -> Self {
        Self { handle }
    }

    pub fn problem_report(
        &self,
        email: &str,
        message: &str,
        log: &str,
        metadata: &BTreeMap<String, String>,
    ) -> impl Future<Output = Result<(), rest::Error>> {
        #[derive(serde::Serialize)]
        struct ProblemReport {
            address: String,
            message: String,
            log: String,
            metadata: BTreeMap<String, String>,
        }

        let report = ProblemReport {
            address: email.to_owned(),
            message: message.to_owned(),
            log: log.to_owned(),
            metadata: metadata.clone(),
        };

        let service = self.handle.service.clone();

        let request = rest::send_json_request(
            &self.handle.factory,
            service,
            "app/v1/problem-report",
            Method::POST,
            &report,
            None,
            &[StatusCode::NO_CONTENT],
        );

        async move {
            request.await?;
            Ok(())
        }
    }
}

#[derive(Clone)]
pub struct AppVersionProxy {
    handle: rest::MullvadRestHandle,
}

#[derive(serde::Deserialize, Debug)]
pub struct AppVersionResponse {
    pub supported: bool,
    pub latest: AppVersion,
    pub latest_stable: Option<AppVersion>,
    pub latest_beta: AppVersion,
}

impl AppVersionProxy {
    pub fn new(handle: rest::MullvadRestHandle) -> Self {
        Self { handle }
    }

    pub fn version_check(
        &self,
        app_version: AppVersion,
        platform: &str,
        platform_version: String,
    ) -> impl Future<Output = Result<AppVersionResponse, rest::Error>> {
        let service = self.handle.service.clone();

        let path = format!("app/v1/releases/{}/{}", platform, app_version);
        let request = self.handle.factory.request(&path, Method::GET);

        async move {
            let mut request = request?;
            request.add_header("M-Platform-Version", &platform_version)?;

            let response = service.request(request).await?;
            let parsed_response = rest::parse_rest_response(response, &[StatusCode::OK]).await?;
            rest::deserialize_body(parsed_response).await
        }
    }
}

/// Error code for when an account has too many keys. Returned when trying to push a new key.
pub const KEY_LIMIT_REACHED: &str = "KEY_LIMIT_REACHED";
#[derive(Clone)]
pub struct WireguardKeyProxy {
    handle: rest::MullvadRestHandle,
}

impl WireguardKeyProxy {
    pub fn new(handle: rest::MullvadRestHandle) -> Self {
        Self { handle }
    }

    pub fn push_wg_key(
        &mut self,
        account_token: AccountToken,
        public_key: wireguard::PublicKey,
        timeout: Option<std::time::Duration>,
    ) -> impl Future<Output = Result<mullvad_types::wireguard::AssociatedAddresses, rest::Error>> + 'static
    {
        #[derive(serde::Serialize)]
        struct PublishRequest {
            pubkey: wireguard::PublicKey,
        }

        let service = self.handle.service.clone();
        let body = PublishRequest { pubkey: public_key };

        let request = self
            .handle
            .factory
            .post_json(&"app/v1/wireguard-keys", &body);
        async move {
            let mut request = request?;
            if let Some(timeout) = timeout {
                request.set_timeout(timeout);
            }
            request.set_auth(Some(account_token))?;
            let response = service.request(request).await?;
            rest::deserialize_body(
                rest::parse_rest_response(response, &[StatusCode::CREATED]).await?,
            )
            .await
        }
    }

    pub async fn replace_wg_key(
        &mut self,
        account_token: AccountToken,
        old: wireguard::PublicKey,
        new: wireguard::PublicKey,
    ) -> Result<mullvad_types::wireguard::AssociatedAddresses, rest::Error> {
        #[derive(serde::Serialize)]
        struct ReplacementRequest {
            old: wireguard::PublicKey,
            new: wireguard::PublicKey,
        }

        let service = self.handle.service.clone();
        let body = ReplacementRequest { old, new };

        let response = rest::send_json_request(
            &self.handle.factory,
            service,
            &"app/v1/replace-wireguard-key",
            Method::POST,
            &body,
            Some(account_token),
            [StatusCode::CREATED, StatusCode::OK].as_slice(),
        )
        .await?;

        rest::deserialize_body(response).await
    }

    pub async fn get_wireguard_key(
        &mut self,
        account_token: AccountToken,
        key: &wireguard::PublicKey,
    ) -> Result<mullvad_types::wireguard::AssociatedAddresses, rest::Error> {
        let service = self.handle.service.clone();

        let response = rest::send_request(
            &self.handle.factory,
            service,
            &format!(
                "app/v1/wireguard-keys/{}",
                urlencoding::encode(&key.to_base64())
            ),
            Method::GET,
            Some(account_token),
            &[StatusCode::OK],
        )
        .await?;

        rest::deserialize_body(response).await
    }

    pub fn remove_wireguard_key(
        &mut self,
        account_token: AccountToken,
        key: wireguard::PublicKey,
    ) -> impl Future<Output = Result<(), rest::Error>> {
        let service = self.handle.service.clone();
        let future = rest::send_request(
            &self.handle.factory,
            service,
            &format!(
                "app/v1/wireguard-keys/{}",
                urlencoding::encode(&key.to_base64())
            ),
            Method::DELETE,
            Some(account_token),
            &[StatusCode::NO_CONTENT],
        );
        async move {
            let _ = future.await?;
            Ok(())
        }
    }
}

#[derive(Clone)]
pub struct ApiProxy {
    handle: rest::MullvadRestHandle,
}

impl ApiProxy {
    pub fn new(handle: rest::MullvadRestHandle) -> Self {
        Self { handle }
    }

    pub async fn get_api_addrs(&self) -> Result<Vec<SocketAddr>, rest::Error> {
        let service = self.handle.service.clone();

        let response = rest::send_request(
            &self.handle.factory,
            service,
            "app/v1/api-addrs",
            Method::GET,
            None,
            &[StatusCode::OK],
        )
        .await?;

        rest::deserialize_body(response).await
    }
}
