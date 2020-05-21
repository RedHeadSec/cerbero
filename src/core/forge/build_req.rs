use super::kdc_req::KdcReqBuilder;
use super::pa_data::{
    new_pa_data_ap_req, new_pa_data_encrypted_timestamp,
    new_pa_data_pa_for_user, new_pa_data_pac_options,
};
use super::principal_name::{new_nt_srv_inst, new_nt_unknown};
use crate::core::forge::KerberosUser;
use crate::core::Cipher;
use kerberos_asn1::{AsReq, TgsReq, Ticket};
use kerberos_constants;
use kerberos_constants::{kdc_options, pa_pac_options};

/// Helper to easily craft an AS-REQ message for asking a TGT
/// from user data
pub fn build_as_req(
    user: KerberosUser,
    cipher: Option<&Cipher>,
    etypes: Option<Vec<i32>>,
) -> AsReq {
    let mut as_req_builder = KdcReqBuilder::new(user.realm)
        .username(user.name)
        .request_pac();

    if let Some(cipher) = cipher {
        let padata = new_pa_data_encrypted_timestamp(cipher);
        as_req_builder = as_req_builder
            .push_padata(padata)
            .etypes(vec![cipher.etype()]);
    }

    if let Some(etypes) = etypes {
        as_req_builder = as_req_builder.etypes(etypes);
    }

    return as_req_builder.build_as_req();
}

/// Helper to easily craft a TGS-REQ message for asking a TGS
/// from user data and TGT
pub fn build_tgs_req(
    user: KerberosUser,
    tgt: Ticket,
    cipher: &Cipher,
    service: &str,
    tgs_imp: Option<Ticket>,
) -> TgsReq {
    let realm = user.realm.clone();
    let sname = new_nt_srv_inst(service);
    let mut tgs_req_builder = KdcReqBuilder::new(realm)
        .push_padata(new_pa_data_ap_req(user, tgt, cipher))
        .sname(Some(sname));

    if let Some(tgs_imp) = tgs_imp {
        tgs_req_builder = tgs_req_builder
            .push_ticket(tgs_imp)
            .add_kdc_option(kdc_options::CONSTRAINED_DELEGATION)
            .push_padata(new_pa_data_pac_options(
                pa_pac_options::RESOURCE_BASED_CONSTRAINED_DELEGATION,
            ));
    }

    return tgs_req_builder.build_tgs_req();
}

/// Helper to easily craft a TGS-REQ message for S4U2Self
/// from user data and TGT
pub fn build_s4u2self_req(
    user: KerberosUser,
    impersonate_user: KerberosUser,
    tgt: Ticket,
    cipher: &Cipher,
) -> TgsReq {
    let realm = user.realm.clone();
    let sname = new_nt_unknown(&user.name);
    let mut tgs_req_builder = KdcReqBuilder::new(realm)
        .push_padata(new_pa_data_ap_req(user, tgt, cipher))
        .sname(Some(sname));

    tgs_req_builder = tgs_req_builder
        .push_padata(new_pa_data_pa_for_user(impersonate_user, cipher));


    return tgs_req_builder.build_tgs_req();
}
