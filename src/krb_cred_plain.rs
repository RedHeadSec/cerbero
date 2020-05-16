use kerberos_constants::principal_names::NT_SRV_INST;
use crate::krb_user::KerberosUser;
use crate::utils::gen_krbtgt_principal_name;
use crate::utils::username_to_principal_name;
use kerberos_asn1::{
    Asn1Object, EncKrbCredPart, EncryptedData, KrbCred, KrbCredInfo,
    PrincipalName, Ticket,
};
use kerberos_constants::etypes::NO_ENCRYPTION;

pub struct KrbCredPlain {
    pub tickets: Vec<Ticket>,
    pub cred_part: EncKrbCredPart,
}

impl KrbCredPlain {
    pub fn try_from_krb_cred(krb_cred: KrbCred) -> Result<Self, String> {
        if krb_cred.enc_part.etype != NO_ENCRYPTION {
            return Err(format!("Unable to decrypt the credentials"));
        }

        let (_, cred_part) = EncKrbCredPart::parse(&krb_cred.enc_part.cipher)
            .map_err(|_| {
            format!("Error parsing credentials: EncKrbCredPart")
        })?;

        return Ok(Self {
            tickets: krb_cred.tickets,
            cred_part: cred_part,
        });
    }

    pub fn look_for_user_creds<'a>(
        &'a self,
        username: &PrincipalName,
        service: &PrincipalName,
    ) -> Option<(&'a Ticket, &'a KrbCredInfo)> {
        for (ticket, cred_info) in
            self.tickets.iter().zip(self.cred_part.ticket_info.iter())
        {
            if let Some(pname) = &cred_info.pname {
                if let Some(sname) = &cred_info.sname {
                    if pname == username && sname == service {
                        return Some((ticket, cred_info));
                    }
                }
            }
        }

        return None;
    }

    pub fn look_for_tgt<'a>(
        &'a self,
        user: KerberosUser,
    ) -> Option<(&'a Ticket, &'a KrbCredInfo)> {
        let cname = username_to_principal_name(user.name);
        let tgt_service = gen_krbtgt_principal_name(user.realm, NT_SRV_INST);

        return self.look_for_user_creds(&cname, &tgt_service);
    }
}

impl Into<KrbCred> for KrbCredPlain {
    fn into(self) -> KrbCred {
        let mut krb_cred = KrbCred::default();
        krb_cred.tickets = self.tickets;
        krb_cred.enc_part =
            EncryptedData::new(NO_ENCRYPTION, None, self.cred_part.build());
        return krb_cred;
    }
}
