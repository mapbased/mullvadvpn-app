use crate::{new_rpc_client, Command, Result};
use clap::value_t;

use mullvad_management_interface::{types as grpc_types, ManagementServiceClient};

use mullvad_types::relay_constraints::{CustomObfuscatorSettings, ObfuscationSettings};

use std::{convert::TryFrom, net::SocketAddr};

pub struct Obfuscation;

#[mullvad_management_interface::async_trait]
impl Command for Obfuscation {
    fn name(&self) -> &'static str {
        "obfuscation"
    }

    fn clap_subcommand(&self) -> clap::App<'static, 'static> {
        clap::SubCommand::with_name(self.name())
            .about("Manage use of obfuscators")
            .setting(clap::AppSettings::SubcommandRequiredElseHelp)
            .subcommand(create_obfuscation_set_subcommand())
            .subcommand(create_obfuscation_get_subcommand())
    }

    async fn run(&self, matches: &clap::ArgMatches<'_>) -> Result<()> {
        match matches.subcommand() {
            ("set", Some(set_matches)) => Self::handle_set(set_matches).await,
            ("get", _) => Self::handle_get().await,
            _ => unreachable!("unhandled command"),
        }
    }
}

impl Obfuscation {
    async fn handle_set(matches: &clap::ArgMatches<'_>) -> Result<()> {
        use talpid_types::net::obfuscation::ObfuscatorType::*;
        match matches.subcommand() {
            ("type", Some(type_matches)) => {
                let obfuscator_type = type_matches.value_of("type").unwrap();
                let mut rpc = new_rpc_client().await?;
                let mut settings = Self::get_obfuscation_settings(&mut rpc).await?;
                settings.active_obfuscator = match obfuscator_type {
                    "none" => None,
                    "mock" => Some(Mock),
                    "custom" => Some(Custom),
                    _ => unreachable!("Unhandled obfuscator type"),
                };
                if settings.active_obfuscator == Some(Custom)
                    && settings.custom_obfuscator_settings.is_none()
                {
                    eprintln!(
                        "Set custom obfuscator settings before enabling the custom obfuscator"
                    );
                    std::process::exit(1);
                }
                Self::set_obfuscation_settings(&mut rpc, &settings).await?;
            }
            ("custom-settings", Some(custom_settings)) => {
                let address = value_t!(custom_settings.value_of("address"), SocketAddr)
                    .unwrap_or_else(|e| e.exit());
                let endpoint = value_t!(custom_settings.value_of("endpoint"), SocketAddr)
                    .unwrap_or_else(|e| e.exit());

                let mut rpc = new_rpc_client().await?;
                let mut settings = Self::get_obfuscation_settings(&mut rpc).await?;

                settings.custom_obfuscator_settings =
                    Some(CustomObfuscatorSettings { address, endpoint });

                Self::set_obfuscation_settings(&mut rpc, &settings).await?;
            }
            _ => unreachable!("unhandled command"),
        }
        Ok(())
    }

    async fn handle_get() -> Result<()> {
        let mut rpc = new_rpc_client().await?;
        let settings = Self::get_obfuscation_settings(&mut rpc).await?;
        println!("{}", settings);
        Ok(())
    }

    async fn get_obfuscation_settings(
        rpc: &mut ManagementServiceClient,
    ) -> Result<ObfuscationSettings> {
        let settings = rpc.get_settings(()).await?.into_inner();

        let obfuscation_settings = ObfuscationSettings::try_from(
            settings
                .obfuscation_settings
                .expect("No obfuscation settnigs"),
        )
        .expect("failed to parse obfuscation settings");
        Ok(obfuscation_settings)
    }

    async fn set_obfuscation_settings(
        rpc: &mut ManagementServiceClient,
        settings: &ObfuscationSettings,
    ) -> Result<()> {
        let grpc_settings: grpc_types::ObfuscationSettings = settings.into();
        let _ = rpc.set_obfuscation_settings(grpc_settings).await?;
        Ok(())
    }
}

fn create_obfuscation_set_subcommand() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("set")
        .about("Set obfuscation settings")
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            clap::SubCommand::with_name("type")
                .about("Set bridge state")
                .arg(
                    clap::Arg::with_name("type")
                        .help("Specifies what kind of obfuscation should be used, if any")
                        .required(true)
                        .index(1)
                        .possible_values(&["none", "mock", "custom"]),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("custom-settings")
                .about("Specifies the config for a custom obfuscator")
                .arg(
                    clap::Arg::with_name("address")
                        .help("Address to which tunnel data will be sent")
                        .required(true)
                        .index(1),
                )
                .arg(
                    clap::Arg::with_name("remote-endpoint")
                        .help("Address of remote endpoint that will be used")
                        .required(true)
                        .index(2),
                ),
        )
}

fn create_obfuscation_get_subcommand() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("get").about("Get obfuscation settings")
}
