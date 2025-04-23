use crate::cesr::{code_b2_to_b64, int_to_b64, nab_sextets, Parsable, Versionage, VERSION};
use crate::errors::MatterError;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::str;

/// GenusCodex is codex of protocol genera for code table.
///
/// Only provides defined codes.
/// Undefined are left out so that inclusion(exclusion) via contains methods works.
#[allow(dead_code)]
pub mod gen_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// KERI, ACDC, and SPAC Protocol Stacks share the same tables
    pub const KERI_ACDC_SPAC: &str = "--AAA";

    /// KERI Protocol Stack
    pub const KERI: &str = "--AAA";

    /// ACDC Protocol Stack
    pub const ACDC: &str = "--AAA";

    /// SPAC Protocol Stack
    pub const SPAC: &str = "--AAA";

    /// Map of genus code names to their values
    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("KERI_ACDC_SPAC", KERI_ACDC_SPAC);
        map.insert("KERI", KERI);
        map.insert("ACDC", ACDC);
        map.insert("SPAC", SPAC);
        map
    });

    /// Tuple of all genus code values
    pub static TUPLE: [&'static str; 4] = [KERI_ACDC_SPAC, KERI, ACDC, SPAC];
}

#[allow(dead_code)]
pub mod ctr_dex_1_0 {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    // Controller Index and Signatures Constants
    pub const CONTROLLER_IDX_SIGS: &str = "-A"; // Qualified Base64 Indexed Signature.
    pub const WITNESS_IDX_SIGS: &str = "-B"; // Qualified Base64 Indexed Signature.
    pub const NON_TRANS_RECEIPT_COUPLES: &str = "-C"; // Composed Base64 Couple, pre+cig.
    pub const TRANS_RECEIPT_QUADRUPLES: &str = "-D"; // Composed Base64 Quadruple, pre+snu+dig+sig.
    pub const FIRST_SEEN_REPLAY_COUPLES: &str = "-E"; // Composed Base64 Couple, fnu+dts.
    pub const TRANS_IDX_SIG_GROUPS: &str = "-F"; // Composed Base64 Group, pre+snu+dig+ControllerIdxSigs group.
    pub const SEAL_SOURCE_COUPLES: &str = "-G"; // Composed Base64 couple, snu+dig of given delegator/issuer/transaction event
    pub const TRANS_LAST_IDX_SIG_GROUPS: &str = "-H"; // Composed Base64 Group, pre+ControllerIdxSigs group.
    pub const SEAL_SOURCE_TRIPLES: &str = "-I"; // Composed Base64 triple, pre+snu+dig of anchoring source event
    pub const SAD_PATH_SIG_GROUPS: &str = "-J"; // Composed Base64 Group path+TransIdxSigGroup of SAID of content
    pub const ROOT_SAD_PATH_SIG_GROUPS: &str = "-K"; // Composed Base64 Group, root(path)+SaidPathCouples
    pub const PATHED_MATERIAL_GROUP: &str = "-L"; // Composed Grouped Pathed Material Quadlet (4 char each)
    pub const BIG_PATHED_MATERIAL_GROUP: &str = "-0L"; // Composed Grouped Pathed Material Quadlet (4 char each)
    pub const ATTACHMENT_GROUP: &str = "-V"; // Composed Grouped Attached Material Quadlet (4 char each)
    pub const BIG_ATTACHMENT_GROUP: &str = "-0V"; // Composed Grouped Attached Material Quadlet (4 char each)
    pub const ESSR_PAYLOAD_GROUP: &str = "-Z"; // ESSR Payload Group, dig of content+Texter group
    pub const KERI_ACDC_GENUS_VERSION: &str = "--AAA"; // KERI ACDC Protocol Stack CESR Version

    // Define a static tuple of all counter codes
    pub static TUPLE: Lazy<Vec<&'static str>> = Lazy::new(|| {
        vec![
            CONTROLLER_IDX_SIGS,
            WITNESS_IDX_SIGS,
            NON_TRANS_RECEIPT_COUPLES,
            TRANS_RECEIPT_QUADRUPLES,
            FIRST_SEEN_REPLAY_COUPLES,
            TRANS_IDX_SIG_GROUPS,
            SEAL_SOURCE_COUPLES,
            TRANS_LAST_IDX_SIG_GROUPS,
            SEAL_SOURCE_TRIPLES,
            SAD_PATH_SIG_GROUPS,
            ROOT_SAD_PATH_SIG_GROUPS,
            PATHED_MATERIAL_GROUP,
            BIG_PATHED_MATERIAL_GROUP,
            ATTACHMENT_GROUP,
            BIG_ATTACHMENT_GROUP,
            ESSR_PAYLOAD_GROUP,
            KERI_ACDC_GENUS_VERSION,
        ]
    });

    // Map counter codes to their descriptive names
    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert(CONTROLLER_IDX_SIGS, "Controller Indexed Signatures");
        map.insert(WITNESS_IDX_SIGS, "Witness Indexed Signatures");
        map.insert(
            NON_TRANS_RECEIPT_COUPLES,
            "Non-Transferable Receipt Couples",
        );
        map.insert(TRANS_RECEIPT_QUADRUPLES, "Transferable Receipt Quadruples");
        map.insert(FIRST_SEEN_REPLAY_COUPLES, "First Seen Replay Couples");
        map.insert(
            TRANS_IDX_SIG_GROUPS,
            "Transferable Indexed Signature Groups",
        );
        map.insert(SEAL_SOURCE_COUPLES, "Seal Source Couples");
        map.insert(
            TRANS_LAST_IDX_SIG_GROUPS,
            "Transferable Last Indexed Signature Groups",
        );
        map.insert(SEAL_SOURCE_TRIPLES, "Seal Source Triples");
        map.insert(SAD_PATH_SIG_GROUPS, "SAD Path Signature Groups");
        map.insert(ROOT_SAD_PATH_SIG_GROUPS, "Root SAD Path Signature Groups");
        map.insert(PATHED_MATERIAL_GROUP, "Pathed Material Group");
        map.insert(BIG_PATHED_MATERIAL_GROUP, "Big Pathed Material Group");
        map.insert(ATTACHMENT_GROUP, "Attachment Group");
        map.insert(BIG_ATTACHMENT_GROUP, "Big Attachment Group");
        map.insert(ESSR_PAYLOAD_GROUP, "ESSR Payload Group");
        map.insert(KERI_ACDC_GENUS_VERSION, "KERI ACDC Genus Version");
        map
    });
}

#[allow(dead_code)]
pub mod ctr_dex_2_0 {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    // Counter Codes for CESR 2.0
    pub const GENERIC_GROUP: &str = "-A"; // Generic Group (Universal with Override).
    pub const BIG_GENERIC_GROUP: &str = "-0A"; // Big Generic Group (Universal with Override).
    pub const MESSAGE_GROUP: &str = "-B"; // Message Body plus Attachments Group (Universal with Override).
    pub const BIG_MESSAGE_GROUP: &str = "-0B"; // Big Message Body plus Attachments Group (Universal with Override).
    pub const ATTACHMENT_GROUP: &str = "-C"; // Message Attachments Only Group (Universal with Override).
    pub const BIG_ATTACHMENT_GROUP: &str = "-0C"; // Big Attachments Only Group (Universal with Override).
    pub const DATAGRAM_SEGMENT_GROUP: &str = "-D"; // Datagram Segment Group (Universal).
    pub const BIG_DATAGRAM_SEGMENT_GROUP: &str = "-0D"; // Big Datagram Segment Group (Universal).
    pub const ESSR_WRAPPER_GROUP: &str = "-E"; // ESSR Wrapper Group (Universal).
    pub const BIG_ESSR_WRAPPER_GROUP: &str = "-0E"; // Big ESSR Wrapper Group (Universal).
    pub const FIXED_MESSAGE_BODY_GROUP: &str = "-F"; // Fixed Field Message Body Group (Universal).
    pub const BIG_FIXED_MESSAGE_BODY_GROUP: &str = "-0F"; // Big Fixed Field Message Body Group (Universal).
    pub const MAP_MESSAGE_BODY_GROUP: &str = "-G"; // Field Map Message Body Group (Universal).
    pub const BIG_MAP_MESSAGE_BODY_GROUP: &str = "-0G"; // Big Field Map Message Body Group (Universal).
    pub const GENERIC_MAP_GROUP: &str = "-H"; // Generic Field Map Group (Universal).
    pub const BIG_GENERIC_MAP_GROUP: &str = "-0H"; // Big Generic Field Map Group (Universal).
    pub const GENERIC_LIST_GROUP: &str = "-I"; // Generic List Group (Universal).
    pub const BIG_GENERIC_LIST_GROUP: &str = "-0I"; // Big Generic List Group (Universal).
    pub const CONTROLLER_IDX_SIGS: &str = "-J"; // Controller Indexed Signature(s) of qb64.
    pub const BIG_CONTROLLER_IDX_SIGS: &str = "-0J"; // Big Controller Indexed Signature(s) of qb64.
    pub const WITNESS_IDX_SIGS: &str = "-K"; // Witness Indexed Signature(s) of qb64.
    pub const BIG_WITNESS_IDX_SIGS: &str = "-0K"; // Big Witness Indexed Signature(s) of qb64.
    pub const NON_TRANS_RECEIPT_COUPLES: &str = "-L"; // NonTrans Receipt Couple(s), pre+cig.
    pub const BIG_NON_TRANS_RECEIPT_COUPLES: &str = "-0L"; // Big NonTrans Receipt Couple(s), pre+cig.
    pub const TRANS_RECEIPT_QUADRUPLES: &str = "-M"; // Trans Receipt Quadruple(s), pre+snu+dig+sig.
    pub const BIG_TRANS_RECEIPT_QUADRUPLES: &str = "-0M"; // Big Trans Receipt Quadruple(s), pre+snu+dig+sig.
    pub const FIRST_SEEN_REPLAY_COUPLES: &str = "-N"; // First Seen Replay Couple(s), fnu+dts.
    pub const BIG_FIRST_SEEN_REPLAY_COUPLES: &str = "-0N"; // First Seen Replay Couple(s), fnu+dts.
    pub const TRANS_IDX_SIG_GROUPS: &str = "-O"; // Trans Indexed Signature Group(s), pre+snu+dig+CtrControllerIdxSigs of qb64.
    pub const BIG_TRANS_IDX_SIG_GROUPS: &str = "-0O"; // Big Trans Indexed Signature Group(s), pre+snu+dig+CtrControllerIdxSigs of qb64.
    pub const TRANS_LAST_IDX_SIG_GROUPS: &str = "-P"; // Trans Last Est Evt Indexed Signature Group(s), pre+CtrControllerIdxSigs of qb64.
    pub const BIG_TRANS_LAST_IDX_SIG_GROUPS: &str = "-0P"; // Big Trans Last Est Evt Indexed Signature Group(s), pre+CtrControllerIdxSigs of qb64.
    pub const SEAL_SOURCE_COUPLES: &str = "-Q"; // Seal Source Couple(s), snu+dig of source sealing or sealed event.
    pub const BIG_SEAL_SOURCE_COUPLES: &str = "-0Q"; // Seal Source Couple(s), snu+dig of source sealing or sealed event.
    pub const SEAL_SOURCE_TRIPLES: &str = "-R"; // Seal Source Triple(s), pre+snu+dig of source sealing or sealed event.
    pub const BIG_SEAL_SOURCE_TRIPLES: &str = "-0R"; // Seal Source Triple(s), pre+snu+dig of source sealing or sealed event.
    pub const PATHED_MATERIAL_GROUP: &str = "-S"; // Pathed Material Group.
    pub const BIG_PATHED_MATERIAL_GROUP: &str = "-0S"; // Big Pathed Material Group.
    pub const SAD_PATH_SIG_GROUPS: &str = "-T"; // SAD Path Group(s) sadpath+CtrTransIdxSigGroup(s) of SAID qb64 of content.
    pub const BIG_SAD_PATH_SIG_GROUPS: &str = "-0T"; // Big SAD Path Group(s) sadpath+CtrTransIdxSigGroup(s) of SAID qb64 of content.
    pub const ROOT_SAD_PATH_SIG_GROUPS: &str = "-U"; // Root Path SAD Path Group(s), rootpath+SadPathGroup(s).
    pub const BIG_ROOT_SAD_PATH_SIG_GROUPS: &str = "-0U"; // Big Root Path SAD Path Group(s), rootpath+SadPathGroup(s).
    pub const DIGEST_SEAL_SINGLES: &str = "-V"; // Digest Seal Single(s), dig of sealed data.
    pub const BIG_DIGEST_SEAL_SINGLES: &str = "-0V"; // Big Digest Seal Single(s), dig of sealed data.
    pub const MERKLE_ROOT_SEAL_SINGLES: &str = "-W"; // Merkle Tree Root Digest Seal Single(s), dig of sealed data.
    pub const BIG_MERKLE_ROOT_SEAL_SINGLES: &str = "-0W"; // Merkle Tree Root Digest Seal Single(s), dig of sealed data.
    pub const BACKER_REGISTRAR_SEAL_COUPLES: &str = "-X"; // Backer Registrar Seal Couple(s), brid+dig of sealed data.
    pub const BIG_BACKER_REGISTRAR_SEAL_COUPLES: &str = "-0X"; // Big Backer Registrar Seal Couple(s), brid+dig of sealed data.
    pub const SEAL_SOURCE_LAST_SINGLES: &str = "-Y"; // Seal Source Couple(s), pre of last source sealing or sealed event.
    pub const BIG_SEAL_SOURCE_LAST_SINGLES: &str = "-0Y"; // Big Seal Source Couple(s), pre of last source sealing or sealed event.
    pub const ESSR_PAYLOAD_GROUP: &str = "-Z"; // ESSR Payload Group.
    pub const BIG_ESSR_PAYLOAD_GROUP: &str = "-0Z"; // Big ESSR Payload Group.
    pub const KERI_ACDC_GENUS_VERSION: &str = "--AAA"; // KERI ACDC Stack CESR Protocol Genus Version (Universal)

    // Define a static tuple of all counter codes
    pub static TUPLE: Lazy<Vec<&'static str>> = Lazy::new(|| {
        vec![
            GENERIC_GROUP,
            BIG_GENERIC_GROUP,
            MESSAGE_GROUP,
            BIG_MESSAGE_GROUP,
            ATTACHMENT_GROUP,
            BIG_ATTACHMENT_GROUP,
            DATAGRAM_SEGMENT_GROUP,
            BIG_DATAGRAM_SEGMENT_GROUP,
            ESSR_WRAPPER_GROUP,
            BIG_ESSR_WRAPPER_GROUP,
            FIXED_MESSAGE_BODY_GROUP,
            BIG_FIXED_MESSAGE_BODY_GROUP,
            MAP_MESSAGE_BODY_GROUP,
            BIG_MAP_MESSAGE_BODY_GROUP,
            GENERIC_MAP_GROUP,
            BIG_GENERIC_MAP_GROUP,
            GENERIC_LIST_GROUP,
            BIG_GENERIC_LIST_GROUP,
            CONTROLLER_IDX_SIGS,
            BIG_CONTROLLER_IDX_SIGS,
            WITNESS_IDX_SIGS,
            BIG_WITNESS_IDX_SIGS,
            NON_TRANS_RECEIPT_COUPLES,
            BIG_NON_TRANS_RECEIPT_COUPLES,
            TRANS_RECEIPT_QUADRUPLES,
            BIG_TRANS_RECEIPT_QUADRUPLES,
            FIRST_SEEN_REPLAY_COUPLES,
            BIG_FIRST_SEEN_REPLAY_COUPLES,
            TRANS_IDX_SIG_GROUPS,
            BIG_TRANS_IDX_SIG_GROUPS,
            TRANS_LAST_IDX_SIG_GROUPS,
            BIG_TRANS_LAST_IDX_SIG_GROUPS,
            SEAL_SOURCE_COUPLES,
            BIG_SEAL_SOURCE_COUPLES,
            SEAL_SOURCE_TRIPLES,
            BIG_SEAL_SOURCE_TRIPLES,
            PATHED_MATERIAL_GROUP,
            BIG_PATHED_MATERIAL_GROUP,
            SAD_PATH_SIG_GROUPS,
            BIG_SAD_PATH_SIG_GROUPS,
            ROOT_SAD_PATH_SIG_GROUPS,
            BIG_ROOT_SAD_PATH_SIG_GROUPS,
            DIGEST_SEAL_SINGLES,
            BIG_DIGEST_SEAL_SINGLES,
            MERKLE_ROOT_SEAL_SINGLES,
            BIG_MERKLE_ROOT_SEAL_SINGLES,
            BACKER_REGISTRAR_SEAL_COUPLES,
            BIG_BACKER_REGISTRAR_SEAL_COUPLES,
            SEAL_SOURCE_LAST_SINGLES,
            BIG_SEAL_SOURCE_LAST_SINGLES,
            ESSR_PAYLOAD_GROUP,
            BIG_ESSR_PAYLOAD_GROUP,
            KERI_ACDC_GENUS_VERSION,
        ]
    });

    // Map counter codes to their descriptive names
    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert(GENERIC_GROUP, "Generic Group");
        map.insert(BIG_GENERIC_GROUP, "Big Generic Group");
        map.insert(MESSAGE_GROUP, "Message Body plus Attachments Group");
        map.insert(BIG_MESSAGE_GROUP, "Big Message Body plus Attachments Group");
        map.insert(ATTACHMENT_GROUP, "Message Attachments Only Group");
        map.insert(BIG_ATTACHMENT_GROUP, "Big Attachments Only Group");
        map.insert(DATAGRAM_SEGMENT_GROUP, "Datagram Segment Group");
        map.insert(BIG_DATAGRAM_SEGMENT_GROUP, "Big Datagram Segment Group");
        map.insert(ESSR_WRAPPER_GROUP, "ESSR Wrapper Group");
        map.insert(BIG_ESSR_WRAPPER_GROUP, "Big ESSR Wrapper Group");
        map.insert(FIXED_MESSAGE_BODY_GROUP, "Fixed Field Message Body Group");
        map.insert(
            BIG_FIXED_MESSAGE_BODY_GROUP,
            "Big Fixed Field Message Body Group",
        );
        map.insert(MAP_MESSAGE_BODY_GROUP, "Field Map Message Body Group");
        map.insert(
            BIG_MAP_MESSAGE_BODY_GROUP,
            "Big Field Map Message Body Group",
        );
        map.insert(GENERIC_MAP_GROUP, "Generic Field Map Group");
        map.insert(BIG_GENERIC_MAP_GROUP, "Big Generic Field Map Group");
        map.insert(GENERIC_LIST_GROUP, "Generic List Group");
        map.insert(BIG_GENERIC_LIST_GROUP, "Big Generic List Group");
        map.insert(CONTROLLER_IDX_SIGS, "Controller Indexed Signatures");
        map.insert(BIG_CONTROLLER_IDX_SIGS, "Big Controller Indexed Signatures");
        map.insert(WITNESS_IDX_SIGS, "Witness Indexed Signatures");
        map.insert(BIG_WITNESS_IDX_SIGS, "Big Witness Indexed Signatures");
        map.insert(
            NON_TRANS_RECEIPT_COUPLES,
            "Non-Transferable Receipt Couples",
        );
        map.insert(
            BIG_NON_TRANS_RECEIPT_COUPLES,
            "Big Non-Transferable Receipt Couples",
        );
        map.insert(TRANS_RECEIPT_QUADRUPLES, "Transferable Receipt Quadruples");
        map.insert(
            BIG_TRANS_RECEIPT_QUADRUPLES,
            "Big Transferable Receipt Quadruples",
        );
        map.insert(FIRST_SEEN_REPLAY_COUPLES, "First Seen Replay Couples");
        map.insert(
            BIG_FIRST_SEEN_REPLAY_COUPLES,
            "Big First Seen Replay Couples",
        );
        map.insert(
            TRANS_IDX_SIG_GROUPS,
            "Transferable Indexed Signature Groups",
        );
        map.insert(
            BIG_TRANS_IDX_SIG_GROUPS,
            "Big Transferable Indexed Signature Groups",
        );
        map.insert(
            TRANS_LAST_IDX_SIG_GROUPS,
            "Transferable Last Indexed Signature Groups",
        );
        map.insert(
            BIG_TRANS_LAST_IDX_SIG_GROUPS,
            "Big Transferable Last Indexed Signature Groups",
        );
        map.insert(SEAL_SOURCE_COUPLES, "Seal Source Couples");
        map.insert(BIG_SEAL_SOURCE_COUPLES, "Big Seal Source Couples");
        map.insert(SEAL_SOURCE_TRIPLES, "Seal Source Triples");
        map.insert(BIG_SEAL_SOURCE_TRIPLES, "Big Seal Source Triples");
        map.insert(PATHED_MATERIAL_GROUP, "Pathed Material Group");
        map.insert(BIG_PATHED_MATERIAL_GROUP, "Big Pathed Material Group");
        map.insert(SAD_PATH_SIG_GROUPS, "SAD Path Signature Groups");
        map.insert(BIG_SAD_PATH_SIG_GROUPS, "Big SAD Path Signature Groups");
        map.insert(ROOT_SAD_PATH_SIG_GROUPS, "Root SAD Path Signature Groups");
        map.insert(
            BIG_ROOT_SAD_PATH_SIG_GROUPS,
            "Big Root SAD Path Signature Groups",
        );
        map.insert(DIGEST_SEAL_SINGLES, "Digest Seal Singles");
        map.insert(BIG_DIGEST_SEAL_SINGLES, "Big Digest Seal Singles");
        map.insert(MERKLE_ROOT_SEAL_SINGLES, "Merkle Root Seal Singles");
        map.insert(BIG_MERKLE_ROOT_SEAL_SINGLES, "Big Merkle Root Seal Singles");
        map.insert(
            BACKER_REGISTRAR_SEAL_COUPLES,
            "Backer Registrar Seal Couples",
        );
        map.insert(
            BIG_BACKER_REGISTRAR_SEAL_COUPLES,
            "Big Backer Registrar Seal Couples",
        );
        map.insert(SEAL_SOURCE_LAST_SINGLES, "Seal Source Last Singles");
        map.insert(BIG_SEAL_SOURCE_LAST_SINGLES, "Big Seal Source Last Singles");
        map.insert(ESSR_PAYLOAD_GROUP, "ESSR Payload Group");
        map.insert(BIG_ESSR_PAYLOAD_GROUP, "Big ESSR Payload Group");
        map.insert(KERI_ACDC_GENUS_VERSION, "KERI ACDC Genus Version");
        map
    });
}

#[allow(dead_code)]
pub mod seal_dex_2_0 {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    // Seal Indexing Constants
    pub const SEAL_SOURCE_COUPLES: &str = "-Q"; // Seal Source Couple(s), snu+dig of source sealing or sealed event.
    pub const BIG_SEAL_SOURCE_COUPLES: &str = "-0Q"; // Seal Source Couple(s), snu+dig of source sealing or sealed event.
    pub const SEAL_SOURCE_TRIPLES: &str = "-R"; // Seal Source Triple(s), pre+snu+dig of source sealing or sealed event.
    pub const BIG_SEAL_SOURCE_TRIPLES: &str = "-0R"; // Seal Source Triple(s), pre+snu+dig of source sealing or sealed event.
    pub const DIGEST_SEAL_SINGLES: &str = "-V"; // Digest Seal Single(s), dig of sealed data.
    pub const BIG_DIGEST_SEAL_SINGLES: &str = "-0V"; // Big Digest Seal Single(s), dig of sealed data.
    pub const MERKLE_ROOT_SEAL_SINGLES: &str = "-W"; // Merkle Tree Root Digest Seal Single(s), dig of sealed data.
    pub const BIG_MERKLE_ROOT_SEAL_SINGLES: &str = "-0W"; // Merkle Tree Root Digest Seal Single(s), dig of sealed data.
    pub const BACKER_REGISTRAR_SEAL_COUPLES: &str = "-X"; // Backer Registrar Seal Couple(s), brid+dig of sealed data.
    pub const BIG_BACKER_REGISTRAR_SEAL_COUPLES: &str = "-0X"; // Big Backer Registrar Seal Couple(s), brid+dig of sealed data.
    pub const SEAL_SOURCE_LAST_SINGLES: &str = "-Y"; // Seal Source Couple(s), pre of last source sealing event.
    pub const BIG_SEAL_SOURCE_LAST_SINGLES: &str = "-0Y"; // Big Seal Source Couple(s), pre of last source sealing event.

    // Define a static tuple of all seal codes
    pub static TUPLE: Lazy<Vec<&'static str>> = Lazy::new(|| {
        vec![
            SEAL_SOURCE_COUPLES,
            BIG_SEAL_SOURCE_COUPLES,
            SEAL_SOURCE_TRIPLES,
            BIG_SEAL_SOURCE_TRIPLES,
            DIGEST_SEAL_SINGLES,
            BIG_DIGEST_SEAL_SINGLES,
            MERKLE_ROOT_SEAL_SINGLES,
            BIG_MERKLE_ROOT_SEAL_SINGLES,
            BACKER_REGISTRAR_SEAL_COUPLES,
            BIG_BACKER_REGISTRAR_SEAL_COUPLES,
            SEAL_SOURCE_LAST_SINGLES,
            BIG_SEAL_SOURCE_LAST_SINGLES,
        ]
    });

    // Map seal codes to their descriptive names
    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert(SEAL_SOURCE_COUPLES, "Seal Source Couples");
        map.insert(BIG_SEAL_SOURCE_COUPLES, "Big Seal Source Couples");
        map.insert(SEAL_SOURCE_TRIPLES, "Seal Source Triples");
        map.insert(BIG_SEAL_SOURCE_TRIPLES, "Big Seal Source Triples");
        map.insert(DIGEST_SEAL_SINGLES, "Digest Seal Singles");
        map.insert(BIG_DIGEST_SEAL_SINGLES, "Big Digest Seal Singles");
        map.insert(MERKLE_ROOT_SEAL_SINGLES, "Merkle Root Seal Singles");
        map.insert(BIG_MERKLE_ROOT_SEAL_SINGLES, "Big Merkle Root Seal Singles");
        map.insert(
            BACKER_REGISTRAR_SEAL_COUPLES,
            "Backer Registrar Seal Couples",
        );
        map.insert(
            BIG_BACKER_REGISTRAR_SEAL_COUPLES,
            "Big Backer Registrar Seal Couples",
        );
        map.insert(SEAL_SOURCE_LAST_SINGLES, "Seal Source Last Singles");
        map.insert(BIG_SEAL_SOURCE_LAST_SINGLES, "Big Seal Source Last Singles");
        map
    });
}

#[derive(Clone, Copy, Debug)]
pub struct Cizage {
    pub hs: u32, // header size
    pub ss: u32, // section size
    pub fs: u32, // field size
}

/// Returns a HashMap mapping CESR counter codes to their size specifications
pub fn get_sizes_1_0() -> HashMap<&'static str, Cizage> {
    let mut sizes = HashMap::new();

    // Add standard counter code sizes
    sizes.insert(
        "-A",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-B",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-C",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-D",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-E",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-F",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-G",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-H",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-I",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-J",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-K",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-L",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );

    // Add big counter code sizes
    sizes.insert(
        "-0L",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );

    // Add seal sizes
    sizes.insert(
        "-V",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-0V",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );

    // Add other special codes
    sizes.insert(
        "-Z",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "--AAA",
        Cizage {
            hs: 5,
            ss: 3,
            fs: 8,
        },
    );

    sizes
}

/// Returns a HashMap mapping CESR 2.0 counter and seal codes to their size specifications
pub fn get_sizes_2_0() -> HashMap<&'static str, Cizage> {
    let mut sizes = HashMap::new();

    // Standard counter codes
    sizes.insert(
        "-A",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-B",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-C",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-D",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-E",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-F",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-G",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-H",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-I",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-J",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-K",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-L",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-M",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-N",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-O",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-P",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-Q",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-R",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-S",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-T",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-U",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-V",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-W",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-X",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-Y",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    sizes.insert(
        "-Z",
        Cizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );

    // Big counter codes
    sizes.insert(
        "-0A",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0B",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0C",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0D",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0E",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0F",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0G",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0H",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0I",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0J",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0K",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0L",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0M",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0N",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0O",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0P",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0Q",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0R",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0S",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0T",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0U",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0V",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0W",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0X",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0Y",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );
    sizes.insert(
        "-0Z",
        Cizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );

    // Special code
    sizes.insert(
        "--AAA",
        Cizage {
            hs: 5,
            ss: 3,
            fs: 8,
        },
    );

    sizes
}

/// Map of hard characters to their respective values
///
/// Includes:
/// - Uppercase letters (A-Z): value 1
/// - Lowercase letters (a-z): value 1
/// - Digits with varying values:
///   - '0','4','5','6': value 2
///   - '1','2','3','7','8','9': value 4
/// Returns a HashMap mapping CESR hard code prefixes to their sizes
pub fn hards() -> HashMap<Vec<u8>, u32> {
    let mut map = HashMap::new();

    // Add uppercase letter codes with size 2
    for c in b'A'..=b'Z' {
        let key = format!("-{}", c as char).into_bytes();
        map.insert(key, 2);
    }

    // Add lowercase letter codes with size 2
    for c in b'a'..=b'z' {
        let key = format!("-{}", c as char).into_bytes();
        map.insert(key, 2);
    }

    // Add special codes
    map.insert(b"-0".to_vec(), 3); // Big code indicator
    map.insert(b"--".to_vec(), 5); // Special index indicator

    map
}

pub static BARDS: Lazy<HashMap<Vec<u8>, u32>> = Lazy::new(|| {
    let mut map = HashMap::new();

    // Special cases with different values
    map.insert(vec![0xfb, 0x40], 3);
    map.insert(vec![0xfb, 0xe0], 5);

    // All other keys with value 2
    // 0xf8 series
    for second_byte in [
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        0xf0,
    ] {
        map.insert(vec![0xf8, second_byte], 2);
    }

    // 0xf9 series
    for second_byte in [
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        0xf0,
    ] {
        map.insert(vec![0xf9, second_byte], 2);
    }

    // 0xfa series
    for second_byte in [
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        0xf0,
    ] {
        map.insert(vec![0xfa, second_byte], 2);
    }

    // 0xfb series with value 2
    for second_byte in [0x00, 0x10, 0x20, 0x30] {
        map.insert(vec![0xfb, second_byte], 2);
    }

    map
});

/// Convert Base64 chars in s to B2 bytes
///
/// Returns bytes that are the conversion (decode) of s Base64 chars to Base2 bytes.
/// The number of total bytes returned is equal to the minimum number of
/// bytes (octets) sufficient to hold the total converted concatenated chars from s,
/// with one sextet per each Base64 char of s. Assumes no pad chars in s.
///
/// Sextets are left aligned with pad bits in last (rightmost) byte to support
/// mid padding of code portion with respect to rest of primitive.
/// This is useful for decoding as bytes, code characters from the front of
/// a Base64 encoded string of characters.
///
/// # Parameters:
///   * `s` - Base64 string to convert
///
pub fn code_b64_to_b2(s: Vec<u8>) -> Vec<u8> {
    // Convert Base64 byte vector to BigUint
    let ss = str::from_utf8(&s).unwrap();

    let i = b64_to_int(ss); // Assuming b64_to_int is modified to accept &[u8]

    // Add 2 bits right zero padding for each sextet
    let padding_bits = 2 * (s.len() % 4);
    let padded_i = i << padding_bits;

    // Compute min number of octets to hold all sextets
    // let n = (s.len() * 3 + 3) / 4; // ceiling of (len(s) * 3 / 4)

    // Convert to bytes in big-endian order
    padded_i.to_bytes_be().to_vec()
}

/// Convert Base64 encoded string to integer
fn b64_to_int(s: &str) -> BigUint {
    let mut result = BigUint::from(0u32);

    for c in s.chars() {
        // Shift existing result by 6 bits (one sextet)
        result <<= 6;

        // Add the value of the current Base64 character
        let val = match c {
            'A'..='Z' => (c as u8 - b'A') as u32,
            'a'..='z' => (c as u8 - b'a' + 26) as u32,
            '0'..='9' => (c as u8 - b'0' + 52) as u32,
            '-' => 62,
            '_' => 63,
            _ => panic!("Invalid Base64 character: {}", c),
        };

        result += BigUint::from(val);
    }

    result
}

// Helper function to calculate power for u64 with overflow checking
fn pow_u64(base: u64, exp: u32) -> u64 {
    base.checked_pow(exp).unwrap_or_else(|| u64::MAX)
}

/// Matter is a trait for fully qualified cryptographic material.
/// Implementations provide various specialized crypto material types.
#[allow(dead_code)]
pub trait Counter {
    /// Returns the hard part of the derivation code
    fn code(&self) -> &str;

    /// Returns the name of the code for this
    fn name(&self) -> &str;

    /// Returns raw crypto material (without derivation code)
    fn count(&self) -> u64;

    /// Returns base64 fully qualified representation
    fn qb64(&self) -> String;

    /// Returns base64 fully qualified representation
    fn qb64b(&self) -> Vec<u8>;

    /// Returns binary fully qualified representation
    fn qb2(&self) -> Vec<u8>;

    /// Returns the hard part of the derivation code
    fn hard(&self) -> &str;

    /// Returns the hard part of the derivation code
    fn soft(&self) -> String;

    /// Returns the hard part of the derivation code
    fn both(&self) -> String;

    /// Full Size
    fn full_size(&self) -> u32;

    /// Return the version
    fn version(&self) -> Result<&Versionage, MatterError>;

    /// Return the version
    fn gvrsn(&self) -> Result<&Versionage, MatterError>;
}

/// Common implementation for all Matter types.
#[derive(Debug)]
pub struct BaseCounter {
    code: String,
    count: u64,
    version: Versionage,
}

impl BaseCounter {
    pub fn from_code_and_count(
        code: Option<&str>,
        count: Option<u64>,
        count_b64: Option<&str>,
    ) -> Result<Self, MatterError> {
        // Get the latest version for codes and sizes
        let gvrsn = VERSION; // assuming VERSION is a global constant similar to Python's gvrsn

        // Use the latest supported version codes and sizes
        let codes = if gvrsn.major == 1 {
            &ctr_dex_1_0::MAP
        } else {
            &ctr_dex_2_0::MAP
        };
        let sizes = if gvrsn.major == 1 {
            &get_sizes_1_0()
        } else {
            &get_sizes_2_0()
        };

        // Process the code provided
        let mut code_str = match code {
            Some(c) => c.to_string(),
            None => return Err(MatterError::InvalidCode("No code provided".to_string())),
        };

        // Check if code is valid
        if !sizes.contains_key(code_str.as_str()) || code_str.len() < 2 {
            // Try to look up code by name
            match codes.get(code_str.as_str()) {
                Some(actual_code) => {
                    code_str = actual_code.to_string();
                    // Verify the actual code is valid
                    if !sizes.contains_key(code_str.as_str()) || code_str.len() < 2 {
                        return Err(MatterError::InvalidCode(format!(
                            "Unsupported code={}",
                            code_str
                        )));
                    }
                }
                None => {
                    return Err(MatterError::InvalidCode(format!(
                        "Unsupported code={}",
                        code_str
                    )));
                }
            }
        }

        // Get sizes for code
        let size = sizes[code_str.as_str()];
        let (hs, ss, fs) = (size.hs, size.ss, size.fs);
        let cs = hs + ss; // both hard + soft code size

        // Validate code size
        if hs < 2 || fs != cs || cs % 4 != 0 {
            return Err(MatterError::InvalidCodeSize(format!(
                "Whole code size not full size or not multiple of 4. cs={} fs={}",
                cs, fs
            )));
        }

        // Process count
        let count_value = match count {
            Some(c) => c,
            None => match count_b64 {
                Some(cb64) => b64_to_int(cb64).to_u64().unwrap_or(1),
                None => 1,
            },
        };

        // Check if we need to dynamically promote the code based on count
        let mut code_str = code_str;
        let mut ss_value = ss;

        if !"-123456789-_".contains(&code_str[1..2]) {
            // small [A-Z,a-z] or large [0]
            if ss != 2 && ss != 5 {
                return Err(MatterError::InvalidVarIndex(format!(
                    "Invalid ss={} for code={}",
                    ss, code_str
                )));
            }

            // Dynamically promote code based on count
            if code_str.chars().nth(1) != Some('0') && count_value > (64u64.pow(2) - 1) {
                // Elevate code due to large count
                code_str = format!("-0{}", code_str.chars().nth(1).unwrap());
                ss_value = 5;
            }
        }

        // Validate count range
        if count_value > (64u64.pow(ss_value) - 1) {
            return Err(MatterError::InvalidVarIndex(format!(
                "Invalid count={} for code={} with ss={}",
                count_value, code_str, ss_value
            )));
        }

        Ok(BaseCounter {
            code: code_str,
            count: count_value,
            version: gvrsn,
        })
    }

    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        if qb64.is_empty() {
            return Err(MatterError::ShortageError(
                "Empty material, Need more characters.".to_string(),
            ));
        }

        // Extract first two char code selector
        if qb64.len() < 2 {
            return Err(MatterError::ShortageError(format!(
                "Need {} more characters.",
                2 - qb64.len()
            )));
        }

        let hards = hards();
        let sizes = &get_sizes_1_0();

        let first = &qb64[..2];
        // .map_err(|_| MatterError::EncodingError("Invalid UTF-8 in code selector".to_string()))?;

        if !hards.contains_key(first.as_bytes()) {
            return Err(MatterError::InvalidCode(format!(
                "Invalid code selector={}",
                first
            )));
        }

        // Get hard code size
        let hs = *hards.get(first.as_bytes()).unwrap() as usize;

        if qb64.len() < hs {
            return Err(MatterError::ShortageError(format!(
                "Need {} more characters.",
                hs - qb64.len()
            )));
        }

        // Get hard code
        let hard = &qb64[..hs];

        if !sizes.contains_key(hard) {
            return Err(MatterError::UnexpectedCodeError(format!(
                "Unsupported code ={}",
                hard
            )));
        }

        // Get sizes for the hard code
        let size = sizes.get(hard).unwrap();
        let (hs, fs) = (size.hs as usize, size.fs as usize);

        // Check if we have enough bytes for the full code
        if qb64.len() < fs {
            return Err(MatterError::ShortageError(format!(
                "Need {} more characters.",
                fs - qb64.len()
            )));
        }

        // Extract count chars
        let count_bytes = &qb64[hs..fs];
        let count_str = str::from_utf8(count_bytes.as_bytes())
            .map_err(|_| MatterError::EncodingError("Invalid UTF-8 in count chars".to_string()))?;

        // Convert base64 to integer
        let count = b64_to_int(count_str)
            .to_u64()
            .ok_or_else(|| MatterError::ValueError("Count value too large for u64".to_string()))?;

        // Update the struct fields
        Ok(BaseCounter {
            code: hard.to_string(),
            count,
            version: VERSION,
        })
    }

    fn bexfil(qb2: &[u8]) -> Result<Self, MatterError> {
        if qb2.is_empty() {
            return Err(MatterError::ShortageError(
                "Empty material, Need more bytes.".to_string(),
            ));
        }
        let sizes = &get_sizes_1_0();

        // Extract first two sextets as code selector
        let first = nab_sextets(qb2, 2)
            .map_err(|e| MatterError::EncodingError(format!("Failed to extract sextets: {}", e)))?;

        if !BARDS.contains_key(&first) {
            // Check if it's an op code (starting with b'\xfc' which is b64ToB2('_'))
            return if first.len() > 0 && first[0] == 0xfc {
                Err(MatterError::UnexpectedOpCodeError(
                    "Unexpected op code start while extracting Matter.".to_string(),
                ))
            } else {
                Err(MatterError::UnexpectedCodeError(format!(
                    "Unsupported code start sextet={:?}",
                    first
                )))
            };
        }

        // Get code hard size equivalent sextets
        let hs = *BARDS.get(&first).unwrap();

        // Calculate bhs (min bytes to hold hs sextets)
        let bhs = ((hs * 3 + 3) / 4) as usize; // ceiling division of hs * 3 / 4

        if qb2.len() < bhs {
            return Err(MatterError::ShortageError(format!(
                "Need {} more bytes.",
                bhs - qb2.len()
            )));
        }

        // Extract and convert hard part of code
        let hard = code_b2_to_b64(qb2, hs as usize)
            .map_err(|e| MatterError::EncodingError(format!("Failed to convert code: {}", e)))?;

        if !sizes.contains_key(hard.as_str()) {
            return Err(MatterError::UnexpectedCodeError(format!(
                "Unsupported code ={}",
                hard
            )));
        }

        // Get sizes for the hard code
        let size = *sizes.get(hard.as_str()).unwrap();
        let (hs, fs) = (size.hs as usize, size.fs as usize);

        // Calculate bcs (min bytes to hold fs sextets)
        let bcs = (fs * 3 + 3) / 4; // ceiling division of fs * 3 / 4

        if qb2.len() < bcs {
            return Err(MatterError::ShortageError(format!(
                "Need {} more bytes.",
                bcs - qb2.len()
            )));
        }

        // Extract and convert both hard and soft part of code
        let both = code_b2_to_b64(qb2, fs)
            .map_err(|e| MatterError::EncodingError(format!("Failed to convert code: {}", e)))?;

        // Get count from the soft part
        let count = b64_to_int(&both[hs..fs])
            .to_u64()
            .ok_or_else(|| MatterError::ValueError("Count value too large for u64".to_string()))?;

        // Update the struct fields
        Ok(BaseCounter {
            code: hard.to_string(),
            count,
            version: VERSION,
        })
    }

    fn infil(&self) -> Result<String, MatterError> {
        let code = &self.code; // codex value chars hard code
        let count = self.count; // index value int used for soft

        let sizes = &get_sizes_1_0();

        // Get size information from the sizes table
        let size = sizes[code.as_str()];
        let ss = size.ss;

        // Verify assumptions:
        // - fs = hs + ss (both hard + soft size)
        // - hs >= 2, ss > 0, fs == hs + ss, and fs is divisible by 4

        // Check if count is in valid range
        let max_count = pow_u64(64, ss).checked_sub(1).ok_or_else(|| {
            MatterError::ValueError("Arithmetic overflow in max count calculation".to_string())
        })?;

        if count > max_count {
            return Err(MatterError::InvalidVarIndexError(format!(
                "Invalid count={} for code={}.",
                count, code
            )));
        }

        // Convert count to base64 with specified length
        let count_b64 = int_to_b64(count as u32, ss as usize);

        // Combine code and count
        let both = format!("{}{}", code, count_b64);

        // Check valid pad size for whole code size
        if both.len() % 4 != 0 {
            return Err(MatterError::InvalidCodeSizeError(format!(
                "Invalid size = {} of {} not a multiple of 4.",
                both.len(),
                both
            )));
        }

        // Return UTF-8 encoded bytes of the combined string
        Ok(both)
    }

    fn binfil(&self) -> Result<Vec<u8>, MatterError> {
        let code = &self.code; // codex chars hard code
        let count = self.count; // index value int used for soft

        let sizes = &get_sizes_1_0();

        // Get size information from the sizes table
        let size = sizes[code.as_str()];
        let (_, ss, fs) = (size.hs, size.ss, size.fs);

        // Verify assumptions:
        // - fs = hs + ss (both hard + soft size)
        // - hs >= 2, ss > 0, fs == hs + ss, and fs is divisible by 4

        // Check if count is in valid range
        let max_count = pow_u64(64, ss).checked_sub(1).ok_or_else(|| {
            MatterError::ValueError("Arithmetic overflow in max count calculation".to_string())
        })?;

        if count > max_count {
            return Err(MatterError::InvalidVarIndexError(format!(
                "Invalid count={} for code={}.",
                count, code
            )));
        }

        // Convert count to base64 with specified length
        let count_b64 = int_to_b64(count as u32, ss as usize);

        // Combine code and count
        let both = format!("{}{}", code, count_b64);

        // Verify the combined code has the expected length
        if both.len() != fs as usize {
            return Err(MatterError::InvalidCodeSizeError(format!(
                "Mismatch code size = {} with table = {}.",
                fs,
                both.len()
            )));
        }

        // Convert the combined base64 code to base2 bytes (binary representation)
        let result = code_b64_to_b2(both.into_bytes());

        Ok(result)
    }
}

impl Parsable for BaseCounter {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let qb64b = data.as_slice();
        let qb64 = str::from_utf8(qb64b).ok();
        let idx = BaseCounter::from_qb64(qb64.unwrap_or(""))?;
        if strip.unwrap_or(false) {
            let fs = idx.full_size();
            data.drain(..fs as usize);
        }
        Ok(idx)
    }

    /// Creates a new BaseMatter from qb2 bytes
    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let qb2 = data.as_slice();
        let idx = BaseCounter::bexfil(qb2)?;
        if strip.unwrap_or(false) {
            let fs = idx.full_size();
            data.drain(..fs as usize);
        }
        Ok(idx)
    }
}

impl Counter for BaseCounter {
    fn code(&self) -> &str {
        &self.code
    }

    /// This is a temporary solution.  If we ever support an annotated stream
    /// We'll have to make this something more than the code.
    fn name(&self) -> &str {
        self.code()
    }

    fn count(&self) -> u64 {
        self.count
    }

    fn qb64(&self) -> String {
        let result = self.infil();
        result.unwrap()
    }

    fn qb64b(&self) -> Vec<u8> {
        let result = self.qb64();
        result.as_bytes().to_vec()
    }

    fn qb2(&self) -> Vec<u8> {
        let result = self.binfil();
        result.unwrap()
    }

    fn hard(&self) -> &str {
        self.code()
    }

    fn soft(&self) -> String {
        let sizes = get_sizes_1_0();
        let size = sizes[self.code.as_str()];
        int_to_b64(self.count() as u32, size.ss as usize)
    }

    fn both(&self) -> String {
        format! {"{}{}", self.code(), self.soft()}
    }

    fn full_size(&self) -> u32 {
        let sizes = &get_sizes_1_0();
        let size = sizes[self.code.as_str()];
        size.fs
    }

    fn version(&self) -> Result<&Versionage, MatterError> {
        Ok(&(self.version))
    }

    fn gvrsn(&self) -> Result<&Versionage, MatterError> {
        self.version()
    }
}

#[cfg(test)]
mod tests {
    use super::gen_dex;
    use super::*;
    use crate::cesr::decode_b64;

    #[test]
    fn test_genus_codes() {
        // Test that all codes have the expected values
        assert_eq!(gen_dex::KERI_ACDC_SPAC, "--AAA");
        assert_eq!(gen_dex::KERI, "--AAA");
        assert_eq!(gen_dex::ACDC, "--AAA");
        assert_eq!(gen_dex::SPAC, "--AAA");

        // Test the MAP
        assert_eq!(gen_dex::MAP.get("KERI_ACDC_SPAC"), Some(&"--AAA"));
        assert_eq!(gen_dex::MAP.get("KERI"), Some(&"--AAA"));
        assert_eq!(gen_dex::MAP.get("ACDC"), Some(&"--AAA"));
        assert_eq!(gen_dex::MAP.get("SPAC"), Some(&"--AAA"));

        // Test the TUPLE
        assert_eq!(gen_dex::TUPLE.len(), 4);
        assert!(gen_dex::TUPLE.contains(&"--AAA"));
    }

    #[test]
    fn test_base_counter_v1() -> Result<(), MatterError> {
        // Test initialization with empty parameters
        // Create code manually
        let count = 1u64;
        let code = ctr_dex_1_0::CONTROLLER_IDX_SIGS.to_string();
        let qsc = format!("{}{}", code, int_to_b64(count as u32, 2));
        assert_eq!(qsc, "-AAB");
        let mut qscb = qsc.as_bytes().to_vec();
        let mut qscb2 = decode_b64(&qsc)?;

        // Test with code and count
        let counter = BaseCounter::from_code_and_count(Some(code.as_str()), Some(count), None)?;
        assert_eq!(counter.code, ctr_dex_1_0::CONTROLLER_IDX_SIGS);
        assert_eq!(counter.name(), "-A");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);
        assert_eq!(counter.full_size(), 4);
        assert_eq!(counter.soft(), "AB");
        assert_eq!(counter.both(), qsc);
        assert_eq!(counter.both(), counter.code.clone() + &counter.soft());
        assert_eq!(counter.both(), counter.qb64());

        // Test with code name and count
        let counter = BaseCounter::from_code_and_count(
            Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS.clone()),
            Some(count),
            None,
        )?;
        assert_eq!(counter.code, ctr_dex_1_0::CONTROLLER_IDX_SIGS);
        assert_eq!(counter.name(), "-A");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);

        // Test with named parameters using code name
        let counter = BaseCounter::from_code_and_count(
            Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS.clone()),
            Some(count),
            None,
        )?;
        assert_eq!(counter.code, ctr_dex_1_0::CONTROLLER_IDX_SIGS);
        assert_eq!(counter.name(), "-A");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);

        // Test with default count = 1
        let counter = BaseCounter::from_code_and_count(
            Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS.clone()),
            Some(1), // Default count = 1
            None,
        )?;
        assert_eq!(counter.code, ctr_dex_1_0::CONTROLLER_IDX_SIGS);
        assert_eq!(counter.name(), "-A");
        assert_eq!(counter.count, count); // Default count is 1
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);

        // Test with qb64 bytes
        let counter = BaseCounter::from_qb64b(&mut qscb, None)?;
        assert_eq!(counter.code, ctr_dex_1_0::CONTROLLER_IDX_SIGS);
        assert_eq!(counter.name(), "-A");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);

        // Test with qb64 string
        let counter = BaseCounter::from_qb64(qsc.as_str())?;
        assert_eq!(counter.code, ctr_dex_1_0::CONTROLLER_IDX_SIGS);
        assert_eq!(counter.name(), "-A");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);

        // Test with qb2
        let counter = BaseCounter::from_qb2(&mut qscb2, None).expect("Failed to decode qb2");
        assert_eq!(counter.code, ctr_dex_1_0::CONTROLLER_IDX_SIGS);
        assert_eq!(counter.name(), "-A");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);

        // Test truncates extra bytes from qb64 parameter
        let long_qsc64 = format!("{}ABCD", qsc);
        let counter = BaseCounter::from_qb64(long_qsc64.as_str())?;
        assert_eq!(counter.qb64().len(), counter.full_size() as usize);

        // Test ShortageError if not enough bytes in qb64 parameter
        let short_qsc64 = qsc[..qsc.len() - 1].to_string();
        let result = BaseCounter::from_qb64(short_qsc64.as_str());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MatterError::ShortageError(_)));

        // Test truncates extra bytes from qb2 parameter
        let mut long_qscb2 = qscb2.clone();
        long_qscb2.extend_from_slice(&[1, 2, 3, 4, 5]);
        let counter = BaseCounter::from_qb2(&mut long_qscb2, None)?;
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.qb64().len(), counter.full_size() as usize);

        // Test ShortageError if not enough bytes in qb2 parameter
        let mut short_qscb2 = qscb2[..qscb2.len() - 1].to_vec();
        let result = BaseCounter::from_qb2(&mut short_qscb2, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MatterError::ShortageError(_)));

        // Test with non-zero count=5
        let count = 5u64;
        let qsc = format!(
            "{}{}",
            ctr_dex_1_0::CONTROLLER_IDX_SIGS,
            int_to_b64(count as u32, 2)
        );
        assert_eq!(qsc, "-AAF");
        let mut qscb = qsc.as_bytes().to_vec();
        let qscb2 = decode_b64(&qsc)?;

        let counter = BaseCounter::from_code_and_count(
            Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS.clone()),
            Some(count),
            None,
        )?;
        assert_eq!(counter.code, ctr_dex_1_0::CONTROLLER_IDX_SIGS);
        assert_eq!(counter.name(), "-A");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);

        // Test with qb64 bytes
        let counter = BaseCounter::from_qb64b(&mut qscb, None)?;
        assert_eq!(counter.code, ctr_dex_1_0::CONTROLLER_IDX_SIGS);
        assert_eq!(counter.name(), "-A");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);

        // Test with big codes index=100024000
        let count = 100024000u64;
        let qsc = format!(
            "{}{}",
            ctr_dex_1_0::BIG_ATTACHMENT_GROUP,
            int_to_b64(count as u32, 5)
        );
        assert_eq!(qsc, "-0VF9j7A");
        let qscb = qsc.as_bytes().to_vec();
        let qscb2 = decode_b64(&qsc)?;

        let counter = BaseCounter::from_code_and_count(
            Some(ctr_dex_1_0::BIG_ATTACHMENT_GROUP.clone()),
            Some(count),
            None,
        )?;
        assert_eq!(counter.code, ctr_dex_1_0::BIG_ATTACHMENT_GROUP);
        assert_eq!(counter.name(), "-0V");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);

        // Test _bexfil and _binfil
        let counter = BaseCounter::from_qb64(qsc.as_str())?;
        // let code = counter.code.clone();
        // let count = counter.count;
        let qb2 = counter.qb2();
        // let mut counter_for_bexfil = counter.clone();
        // counter_for_bexfil._bexfil(&qb2)?;
        // assert_eq!(counter_for_bexfil.code, code);
        // assert_eq!(counter_for_bexfil.name(), "BigAttachmentGroup");
        // assert_eq!(counter_for_bexfil.count, count);
        // assert_eq!(counter_for_bexfil.qb64(), qsc);
        // assert_eq!(counter_for_bexfil.qb2(), qb2);
        // assert_eq!(counter_for_bexfil.version.major, 1);
        // assert_eq!(counter_for_bexfil.version.minor, 0);

        // Test _binfil
        let test = counter.binfil()?;
        assert_eq!(test, qb2);

        // Test with big pathed material group
        let count = 100024000u64;
        let qsc = format!(
            "{}{}",
            ctr_dex_1_0::BIG_PATHED_MATERIAL_GROUP,
            int_to_b64(count as u32, 5)
        );
        assert_eq!(qsc, "-0LF9j7A");
        let qscb = qsc.as_bytes().to_vec();
        let qscb2 = decode_b64(&qsc)?;

        let counter = BaseCounter::from_code_and_count(
            Some(ctr_dex_1_0::BIG_PATHED_MATERIAL_GROUP.clone()),
            Some(count),
            None,
        )?;
        assert_eq!(counter.code, ctr_dex_1_0::BIG_PATHED_MATERIAL_GROUP);
        assert_eq!(counter.name(), "-0L");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);

        // Test strip functionality
        let count = 1u64;
        let qsc = format!(
            "{}{}",
            ctr_dex_1_0::CONTROLLER_IDX_SIGS,
            int_to_b64(count as u32, 2)
        );
        assert_eq!(qsc, "-AAB");
        let qscb = qsc.as_bytes().to_vec();
        let qscb2 = decode_b64(&qsc)?;

        // strip ignored if qb64 is String
        let counter = BaseCounter::from_qb64(qsc.as_str())?;
        assert_eq!(counter.code, ctr_dex_1_0::CONTROLLER_IDX_SIGS);
        assert_eq!(counter.name(), "-A");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);

        // Test with longer buffer for qb64b
        // let mut ims = qscb.clone();
        // let extra = b"ABCD".to_vec();
        // ims.extend_from_slice(&extra);
        // let ims_clone = ims.clone();
        // let counter = BaseCounter::from_qb64b(
        //     Some(ims_clone.as_slice()),
        // )?;
        // assert_eq!(counter.qb64b(), qscb);
        // assert_eq!(counter.qb64b().len(), counter.full_size() as usize);
        // assert_eq!(ims_clone, extra);

        // Test with longer buffer for qb2
        // let mut ims = qscb2.clone();
        // let extra = vec![1, 2, 3, 4, 5];
        // ims.extend_from_slice(&extra);
        // let ims_clone = ims.clone();
        // let counter = BaseCounter::from_qb64b(
        //     Some(ims_clone.as_slice()),
        // )?;
        // assert_eq!(counter.qb2(), qscb2);
        // assert_eq!(counter.qb2().len(), (counter.full_size() * 3 / 4) as usize);
        // assert_eq!(ims_clone, extra);

        // Test with big codes index=1024
        let count = 1024u64;
        let qsc = format!(
            "{}{}",
            ctr_dex_1_0::BIG_ATTACHMENT_GROUP,
            int_to_b64(count as u32, 5)
        );
        assert_eq!(qsc, "-0VAAAQA");
        let qscb = qsc.as_bytes().to_vec();
        let qscb2 = decode_b64(&qsc)?;

        let mut ims = qscb.clone();
        let counter = BaseCounter::from_qb64b(&mut ims, None)?;
        assert_eq!(counter.code, ctr_dex_1_0::BIG_ATTACHMENT_GROUP);
        assert_eq!(counter.name(), "-0V");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);
        assert_eq!(counter.full_size(), 8);
        // Doesn't support strip yet
        // assert_eq!(ims.len(), 0); // Consumed/stripped

        let mut ims = qscb2.clone();
        let counter = BaseCounter::from_qb2(&mut ims, None)?;
        assert_eq!(counter.code, ctr_dex_1_0::BIG_ATTACHMENT_GROUP);
        assert_eq!(counter.name(), "-0V");
        assert_eq!(counter.count, count);
        assert_eq!(counter.qb64b(), qscb);
        assert_eq!(counter.qb64(), qsc);
        assert_eq!(counter.qb2(), qscb2);
        assert_eq!(counter.version.major, 1);
        assert_eq!(counter.version.minor, 0);
        assert_eq!(counter.full_size(), 8);
        // Doesn't support strip yet
        // assert_eq!(ims.len(), 0); // Consumed/stripped

        Ok(())
    }
}
