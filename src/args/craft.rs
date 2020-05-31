use super::validators;
use crate::core::CredentialFormat;
use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use kerberos_crypto::Key;
use ms_pac::PISID;
use std::convert::TryInto;

pub const COMMAND_NAME: &str = "craft";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("Create golden and silver tickets")
        .arg(
            Arg::with_name("realm")
                .long("realm")
                .visible_alias("domain")
                .short("d")
                .takes_value(true)
                .help("Domain/Realm for ticket")
                .required(true),
        )
        .arg(
            Arg::with_name("realm-sid")
                .long("realm-sid")
                .visible_alias("domain-sid")
                .takes_value(true)
                .help("SID of the Domain/Realm for ticket")
                .required(true)
                .validator(validators::is_sid),
        )
        .arg(
            Arg::with_name("user")
                .long("user")
                .short("u")
                .takes_value(true)
                .help("Username for ticket")
                .required(true),
        )
        .arg(
            Arg::with_name("user-rid")
                .long("user-rid")
                .takes_value(true)
                .help("User RID for the ticket")
                .default_value("500")
                .validator(validators::is_u32),
        )
        .arg(
            Arg::with_name("service")
                .long("service")
                .visible_alias("spn")
                .takes_value(true)
                .value_name("spn")
                .help("SPN of the desired service"),
        )
        .arg(
            Arg::with_name("password")
                .long("password")
                .short("p")
                .takes_value(true)
                .help("Password of user"),
        )
        .arg(
            Arg::with_name("rc4")
                .long("rc4")
                .visible_alias("ntlm")
                .takes_value(true)
                .help("RC4 Kerberos key (NTLM hash of user) for encrypt and sign the ticket")
                .validator(validators::is_rc4_key),
        )
        .arg(
            Arg::with_name("aes-128")
                .long("aes-128")
                .takes_value(true)
                .help("AES 128 Kerberos key for encrypt and sign the ticket")
                .validator(validators::is_aes_128_key),
        )
        .arg(
            Arg::with_name("aes-256")
                .long("aes-256")
                .takes_value(true)
                .help("AES 256 Kerberos key for encrypt and sign the ticket")
                .validator(validators::is_aes_256_key),
        )
        .group(
            ArgGroup::with_name("user_key")
                .args(&["password", "rc4", "aes-128", "aes-256"])
                .multiple(false)
                .required(true)
        )
        .arg(
            Arg::with_name("groups")
                .long("groups")
                .alias("groups-rid")
                .takes_value(true)
                .use_delimiter(true)
                .help("RIDs of groups to include in ticket")
                .default_value("513,512,520,518,519")
                .validator(validators::is_u32),
        )
        .arg(
            Arg::with_name("cred-format")
                .long("cred-format")
                .alias("ticket-format")
                .takes_value(true)
                .possible_values(&["krb", "ccache"])
                .help("Format to save retrieved tickets.")
                .default_value("ccache"),
        )
        .arg(
            Arg::with_name("cred-file")
                .long("cred-file")
                .visible_alias("ticket-file")
                .takes_value(true)
                .value_name("file")
                .help("File to save ticket"),
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Increase message verbosity"),
        )
}

pub struct Arguments {
    pub realm: String,
    pub realm_sid: PISID,
    pub username: String,
    pub user_rid: u32,
    pub service: Option<String>,
    pub key: Key,
    pub groups: Vec<u32>,
    pub credential_format: CredentialFormat,
    pub credential_file: Option<String>,
    pub verbosity: usize,
}

pub struct ArgumentsParser<'a> {
    matches: &'a ArgMatches<'a>,
}

impl<'a> ArgumentsParser<'a> {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {
        let parser = Self { matches: matches };
        return parser._parse();
    }

    fn _parse(&self) -> Arguments {
        return Arguments {
            realm: self.parse_string("realm"),
            realm_sid: self.parse_realm_sid(),
            username: self.parse_string("user"),
            user_rid: self.parse_u32("user-rid"),
            service: self.parse_service(),
            key: self.parse_key(),
            groups: self.parse_groups(),
            credential_format: self.parse_credential_format(),
            credential_file: self.parse_credential_file(),
            verbosity: self.parse_verbosity(),
        };
    }

    fn parse_groups(&self) -> Vec<u32> {
        self.matches
            .values_of("groups")
            .unwrap()
            .map(|g| g.parse().unwrap())
            .collect()
    }

    fn parse_verbosity(&self) -> usize {
        self.matches.occurrences_of("verbosity") as usize
    }

    fn parse_key(&self) -> Key {
        if let Some(password) = self.matches.value_of("password") {
            return Key::Secret(password.to_string());
        } else if let Some(ntlm) = self.matches.value_of("rc4") {
            return Key::from_rc4_key_string(ntlm).unwrap();
        } else if let Some(aes_128_key) = self.matches.value_of("aes-128") {
            return Key::from_aes_128_key_string(aes_128_key).unwrap();
        } else if let Some(aes_256_key) = self.matches.value_of("aes-256") {
            return Key::from_aes_256_key_string(aes_256_key).unwrap();
        }

        unreachable!("Unknown provided key")
    }

    fn parse_service(&self) -> Option<String> {
        return self.matches.value_of("service").map(|s| s.into());
    }

    fn parse_realm_sid(&self) -> PISID {
        self.matches
            .value_of("realm-sid")
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn parse_string(&self, name: &str) -> String {
        self.matches.value_of(name).unwrap().into()
    }

    fn parse_u32(&self, name: &str) -> u32 {
        self.matches.value_of(name).unwrap().parse().unwrap()
    }

    fn parse_credential_format(&self) -> CredentialFormat {
        let format = self.matches.value_of("cred-format").unwrap();

        if format == "krb" {
            return CredentialFormat::Krb;
        }

        return CredentialFormat::Ccache;
    }

    fn parse_credential_file(&self) -> Option<String> {
        return self.matches.value_of("cred-file").map(|s| s.into());
    }
}
