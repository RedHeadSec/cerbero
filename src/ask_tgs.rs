use crate::ask_tgt::request_tgt;
use crate::cred_format::CredentialFormat;
use kerberos_asn1::{
    ApReq, Asn1Object, Authenticator, EncTgsRepPart, EncryptedData,
    KrbCredInfo, PaData, PaForUser, PaPacOptions, PrincipalName, TgsRep,
    TgsReq, Ticket,
};

use kerberos_constants::checksum_types;
use kerberos_constants::kdc_options;
use kerberos_constants::key_usages;
use kerberos_constants::key_usages::{
    KEY_USAGE_KERB_NON_KERB_CKSUM_SALT, KEY_USAGE_TGS_REQ_AUTHEN,
};
use kerberos_constants::pa_data_types::PA_PAC_OPTIONS;
use kerberos_constants::pa_data_types::{PA_FOR_USER, PA_TGS_REQ};
use kerberos_constants::pa_pac_options;
use kerberos_constants::principal_names::{NT_SRV_INST, NT_UNKNOWN};
use kerberos_crypto::{checksum_hmac_md5, new_kerberos_cipher, Key};

use crate::kdc_req_builder::KdcReqBuilder;
use crate::senders::{send_recv, Rep};

use crate::error::Result;
use crate::file::{parse_creds_file, save_cred_in_file};
use crate::krb_cred_plain::KrbCredPlain;
use crate::krb_user::KerberosUser;
use crate::transporter::KerberosTransporter;
use crate::utils::{create_krb_cred_info, username_to_principal_name};

pub fn ask_tgs(
    user: KerberosUser,
    service: String,
    creds_file: &str,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredentialFormat,
) -> Result<()> {
    let (mut krb_cred_plain, cred_format, ticket, krb_cred_info) =
        get_user_tgt(
            user.clone(),
            creds_file,
            user_key,
            transporter,
            cred_format,
        )?;

    let (tgs, krb_cred_info_tgs) = request_tgs(
        user,
        service,
        &krb_cred_info,
        ticket.clone(),
        transporter,
    )?;

    krb_cred_plain.cred_part.ticket_info.push(krb_cred_info_tgs);
    krb_cred_plain.tickets.push(tgs);

    save_cred_in_file(krb_cred_plain.into(), &cred_format, creds_file)?;

    return Ok(());
}

fn get_user_tgt(
    user: KerberosUser,
    creds_file: &str,
    user_key: Option<&Key>,
    transporter: &dyn KerberosTransporter,
    cred_format: CredentialFormat,
) -> Result<(KrbCredPlain, CredentialFormat, Ticket, KrbCredInfo)> {
    match get_user_tgt_from_file(user.clone(), creds_file) {
        Ok(ok) => return Ok(ok),
        Err(_) => match user_key {
            Some(user_key) => {
                let krb_cred = request_tgt(&user, user_key, true, transporter)?;
                let krb_cred_plain = KrbCredPlain::try_from_krb_cred(krb_cred)?;

                let (ticket, krb_cred_info) =
                    krb_cred_plain.look_for_tgt(user.clone()).unwrap();

                return Ok((
                    krb_cred_plain,
                    cred_format,
                    ticket,
                    krb_cred_info,
                ));
            }
            None => {
                return Err("Unable to request TGT without user credentials")?;
            }
        },
    }
}

fn get_user_tgt_from_file(
    user: KerberosUser,
    creds_file: &str,
) -> Result<(KrbCredPlain, CredentialFormat, Ticket, KrbCredInfo)> {
    let (krb_cred, cred_format) = parse_creds_file(creds_file)?;
    let krb_cred_plain = KrbCredPlain::try_from_krb_cred(krb_cred)?;

    let (ticket, krb_cred_info) = krb_cred_plain
        .look_for_tgt(user.clone())
        .ok_or(format!("No TGT found for '{}", user.name))?;

    return Ok((krb_cred_plain, cred_format, ticket, krb_cred_info));
}

fn request_tgs(
    user: KerberosUser,
    service: String,
    krb_cred_info: &KrbCredInfo,
    ticket: Ticket,
    transporter: &dyn KerberosTransporter,
) -> Result<(Ticket, KrbCredInfo)> {
    let session_key = &krb_cred_info.key.keyvalue;
    let tgs_req = build_tgs_req(user, service, krb_cred_info, ticket)?;

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    let enc_tgs_as_rep_raw =
        decrypt_tgs_rep_enc_part(session_key, &tgs_rep.enc_part)?;

    let (_, enc_tgs_rep_part) = EncTgsRepPart::parse(&enc_tgs_as_rep_raw)
        .map_err(|_| format!("Error parsing EncTgsRepPart"))?;

    let krb_cred_info_tgs = create_krb_cred_info(
        enc_tgs_rep_part.into(),
        tgs_rep.crealm,
        tgs_rep.cname,
    );

    return Ok((tgs_rep.ticket, krb_cred_info_tgs));
}

fn send_recv_tgs(
    transporter: &dyn KerberosTransporter,
    req: &TgsReq,
) -> Result<TgsRep> {
    let rep = send_recv(transporter, &req.build())
        .map_err(|err| format!("Error sending TGS-REQ: {}", err))?;

    match rep {
        Rep::KrbError(krb_error) => {
            return Err(krb_error)?;
        }

        Rep::Raw(_) => {
            return Err("Error parsing response")?;
        }

        Rep::AsRep(_) => {
            return Err("Unexpected: server responded with AS-REP to TGS-REQ")?;
        }

        Rep::TgsRep(tgs_rep) => {
            return Ok(tgs_rep);
        }
    }
}

fn build_tgs_req(
    user: KerberosUser,
    service: String,
    krb_cred_info: &KrbCredInfo,
    ticket: Ticket,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &krb_cred_info.key.keyvalue;

    let service_parts: Vec<String> =
        service.split("/").map(|s| s.to_string()).collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: service_parts,
    };

    let cname = username_to_principal_name(user.name);
    let mut authenticator = Authenticator::default();
    authenticator.crealm = user.realm.clone();
    authenticator.cname = cname;

    let authen_etype = krb_cred_info.key.keytype;
    let cipher = new_kerberos_cipher(authen_etype)
        .map_err(|_| format!("No supported etype: {}", authen_etype))?;

    let encrypted_authenticator = cipher.encrypt(
        session_key,
        KEY_USAGE_TGS_REQ_AUTHEN,
        &authenticator.build(),
    );

    let mut ap_req = ApReq::default();
    ap_req.ticket = ticket;
    ap_req.authenticator = EncryptedData {
        etype: authen_etype,
        kvno: None,
        cipher: encrypted_authenticator,
    };

    padatas.push(PaData::new(PA_TGS_REQ, ap_req.build()));

    let tgs_req = KdcReqBuilder::new(user.realm)
        .padatas(padatas)
        .sname(Some(sname))
        .build_tgs_req();

    return Ok(tgs_req);
}

fn decrypt_tgs_rep_enc_part(
    session_key: &[u8],
    enc_part: &EncryptedData,
) -> Result<Vec<u8>> {
    let cipher = new_kerberos_cipher(enc_part.etype)
        .map_err(|_| format!("Not supported etype: '{}'", enc_part.etype))?;

    let raw_enc_as_req_part = cipher
        .decrypt(
            session_key,
            key_usages::KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY,
            &enc_part.cipher,
        )
        .map_err(|error| format!("Error decrypting TGS-REP: {}", error))?;

    return Ok(raw_enc_as_req_part);
}

fn create_pa_for_user(user: KerberosUser, session_key: &[u8]) -> PaForUser {
    let mut pa_for_user = PaForUser::default();
    pa_for_user.username = username_to_principal_name(user.name);
    pa_for_user.userrealm = user.realm;
    pa_for_user.auth_package = "Kerberos".to_string();

    let mut ck_value = pa_for_user.username.name_type.to_le_bytes().to_vec();
    ck_value
        .append(&mut pa_for_user.username.name_string[0].clone().into_bytes());
    ck_value.append(&mut pa_for_user.userrealm.clone().into_bytes());
    ck_value.append(&mut pa_for_user.auth_package.clone().into_bytes());

    let cksum = checksum_hmac_md5(
        session_key,
        KEY_USAGE_KERB_NON_KERB_CKSUM_SALT,
        &ck_value,
    );

    pa_for_user.cksum.cksumtype = checksum_types::HMAC_MD5;
    pa_for_user.cksum.checksum = cksum;

    return pa_for_user;
}

pub fn ask_s4u2self(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    creds_file: &str,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredentialFormat,
) -> Result<()> {
    let (mut krb_cred_plain, cred_format, ticket, krb_cred_info) =
        get_user_tgt(
            user.clone(),
            creds_file,
            user_key,
            transporter,
            cred_format,
        )?;

    let (tgs, krb_cred_info_tgs) = request_s4u2self(
        user,
        impersonate_user,
        &krb_cred_info,
        ticket.clone(),
        transporter,
    )?;

    krb_cred_plain.cred_part.ticket_info.push(krb_cred_info_tgs);
    krb_cred_plain.tickets.push(tgs);

    save_cred_in_file(krb_cred_plain.into(), &cred_format, creds_file)?;

    return Ok(());
}

fn request_s4u2self(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    krb_cred_info: &KrbCredInfo,
    ticket: Ticket,
    transporter: &dyn KerberosTransporter,
) -> Result<(Ticket, KrbCredInfo)> {
    let session_key = &krb_cred_info.key.keyvalue;
    let tgs_req =
        build_s4u2self_req(user, impersonate_user, krb_cred_info, ticket)?;

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    let enc_tgs_as_rep_raw =
        decrypt_tgs_rep_enc_part(session_key, &tgs_rep.enc_part)?;

    let (_, enc_tgs_rep_part) = EncTgsRepPart::parse(&enc_tgs_as_rep_raw)
        .map_err(|_| format!("Error parsing EncTgsRepPart"))?;

    let krb_cred_info_tgs = create_krb_cred_info(
        enc_tgs_rep_part.into(),
        tgs_rep.crealm,
        tgs_rep.cname,
    );

    return Ok((tgs_rep.ticket, krb_cred_info_tgs));
}

fn build_s4u2self_req(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    krb_cred_info: &KrbCredInfo,
    ticket: Ticket,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &krb_cred_info.key.keyvalue;

    let pa_for_user = create_pa_for_user(impersonate_user, session_key);
    padatas.push(PaData::new(PA_FOR_USER, pa_for_user.build()));

    let sname = PrincipalName {
        name_type: NT_UNKNOWN,
        name_string: vec![user.name.clone()],
    };

    let cname = username_to_principal_name(user.name);
    let mut authenticator = Authenticator::default();
    authenticator.crealm = user.realm.clone();
    authenticator.cname = cname;

    let authen_etype = krb_cred_info.key.keytype;
    let cipher = new_kerberos_cipher(authen_etype)
        .map_err(|_| format!("No supported etype: {}", authen_etype))?;

    let encrypted_authenticator = cipher.encrypt(
        session_key,
        KEY_USAGE_TGS_REQ_AUTHEN,
        &authenticator.build(),
    );

    let mut ap_req = ApReq::default();
    ap_req.ticket = ticket;
    ap_req.authenticator = EncryptedData {
        etype: authen_etype,
        kvno: None,
        cipher: encrypted_authenticator,
    };

    padatas.push(PaData::new(PA_TGS_REQ, ap_req.build()));

    let tgs_req = KdcReqBuilder::new(user.realm)
        .padatas(padatas)
        .sname(Some(sname))
        .build_tgs_req();

    return Ok(tgs_req);
}

pub fn ask_s4u2proxy(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    service: String,
    creds_file: &str,
    transporter: &dyn KerberosTransporter,
    user_key: Option<&Key>,
    cred_format: CredentialFormat,
) -> Result<()> {
    let (krb_cred_plain, cred_format, tgt, krb_cred_info) =
        get_user_tgt(
            user.clone(),
            creds_file,
            user_key,
            transporter,
            cred_format,
        )?;

    let (mut krb_cred_plain, imp_ticket) = get_impersonation_ticket(
        krb_cred_plain,
        user.clone(),
        impersonate_user,
        transporter,
        &krb_cred_info,
        tgt.clone(),
    )?;

    let (tgs, krb_cred_info_tgs) = request_s4u2proxy(
        user,
        service,
        &krb_cred_info,
        tgt,
        imp_ticket,
        transporter,
    )?;

    krb_cred_plain.cred_part.ticket_info.push(krb_cred_info_tgs);
    krb_cred_plain.tickets.push(tgs);

    save_cred_in_file(krb_cred_plain.into(), &cred_format, creds_file)?;

    return Ok(());
}

fn get_impersonation_ticket(
    mut krb_cred_plain: KrbCredPlain,
    user: KerberosUser,
    impersonate_user: KerberosUser,
    transporter: &dyn KerberosTransporter,
    krb_cred_info: &KrbCredInfo,
    tgt: Ticket,
) -> Result<(KrbCredPlain, Ticket)> {
    let result = krb_cred_plain
        .look_for_impersonation_ticket(user.name.clone(), impersonate_user.name.clone());

    match result {
        Some((imp_ticket, _)) => {
            return Ok((krb_cred_plain, imp_ticket));
        }
        None => {
            let (imp_ticket, krb_cred_info_tgs) = request_s4u2self(
                user,
                impersonate_user,
                &krb_cred_info,
                tgt,
                transporter,
            )?;
            
            krb_cred_plain.cred_part.ticket_info.push(krb_cred_info_tgs);
            krb_cred_plain.tickets.push(imp_ticket.clone());

            return Ok((krb_cred_plain, imp_ticket));
        }
    }
}

fn request_s4u2proxy(
    user: KerberosUser,
    service: String,
    krb_cred_info: &KrbCredInfo,
    ticket: Ticket,
    ticket_imp: Ticket,
    transporter: &dyn KerberosTransporter,
) -> Result<(Ticket, KrbCredInfo)> {
    let session_key = &krb_cred_info.key.keyvalue;
    let tgs_req =
        build_s4u2proxy_req(user, service, krb_cred_info, ticket, ticket_imp)?;

    let tgs_rep = send_recv_tgs(transporter, &tgs_req)?;

    let enc_tgs_as_rep_raw =
        decrypt_tgs_rep_enc_part(session_key, &tgs_rep.enc_part)?;

    let (_, enc_tgs_rep_part) = EncTgsRepPart::parse(&enc_tgs_as_rep_raw)
        .map_err(|_| format!("Error parsing EncTgsRepPart"))?;

    let krb_cred_info_tgs = create_krb_cred_info(
        enc_tgs_rep_part.into(),
        tgs_rep.crealm,
        tgs_rep.cname,
    );

    return Ok((tgs_rep.ticket, krb_cred_info_tgs));
}

fn build_s4u2proxy_req(
    user: KerberosUser,
    service: String,
    krb_cred_info: &KrbCredInfo,
    ticket: Ticket,
    ticket_imp: Ticket,
) -> Result<TgsReq> {
    let mut padatas = Vec::new();
    let session_key = &krb_cred_info.key.keyvalue;

    let service_parts: Vec<String> =
        service.split("/").map(|s| s.to_string()).collect();
    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: service_parts,
    };

    let pac_options = PaPacOptions {
        kerberos_flags: pa_pac_options::RESOURCE_BASED_CONSTRAINED_DELEGATION
            .into(),
    };

    padatas.push(PaData::new(PA_PAC_OPTIONS, pac_options.build()));

    let cname = username_to_principal_name(user.name);
    let mut authenticator = Authenticator::default();
    authenticator.crealm = user.realm.clone();
    authenticator.cname = cname;

    let authen_etype = krb_cred_info.key.keytype;
    let cipher = new_kerberos_cipher(authen_etype)
        .map_err(|_| format!("No supported etype: {}", authen_etype))?;

    let encrypted_authenticator = cipher.encrypt(
        session_key,
        KEY_USAGE_TGS_REQ_AUTHEN,
        &authenticator.build(),
    );

    let mut ap_req = ApReq::default();
    ap_req.ticket = ticket;
    ap_req.authenticator = EncryptedData {
        etype: authen_etype,
        kvno: None,
        cipher: encrypted_authenticator,
    };

    padatas.push(PaData::new(PA_TGS_REQ, ap_req.build()));

    let tgs_req = KdcReqBuilder::new(user.realm)
        .padatas(padatas)
        .sname(Some(sname))
        .push_ticket(ticket_imp)
        .add_kdc_option(kdc_options::CONSTRAINED_DELEGATION)
        .build_tgs_req();

    return Ok(tgs_req);
}
