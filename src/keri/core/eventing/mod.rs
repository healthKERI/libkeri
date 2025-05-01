use crate::Matter;
use std::error::Error;

use crate::cesr::cigar::Cigar;
use crate::cesr::non_trans_dex;
use crate::cesr::seqner::Seqner;
use crate::keri::core::serdering::{Serder, SerderKERI};

mod incept;
mod interact;
mod query;
mod receipt;
mod reply;
mod rotate;

use crate::cesr::counting::{ctr_dex_1_0, BaseCounter, Counter};
use crate::cesr::indexing::siger::Siger;
pub use incept::*;

// Determine threshold representations based on intive flag
const MAX_INT_THOLD: usize = 12; // Define this constant based on your system

fn ample(n: usize) -> usize {
    // Implementation for ample - computes witness threshold
    std::cmp::max(1, (n as f64 / 2.0).ceil() as usize)
}

fn is_digest_code(code: &str) -> bool {
    // Check if code is in DigDex
    ["E", "S", "X"].contains(&code)
}

fn is_prefix_code(code: &str) -> bool {
    // Check if code is in PreDex
    ["A", "B", "C", "D"].contains(&code)
}

/// SealEvent represents a triple (i, s, d) of identifier, sequence number, and digest
#[derive(Debug, Clone)]
pub struct SealEvent {
    pub i: String, // identifier prefix (pre)
    pub s: String, // sequence number as hex string
    pub d: String, // digest (said)
}

impl SealEvent {
    pub fn new(i: String, s: String, d: String) -> Self {
        Self { i, s, d }
    }
}

/// SealLast represents a single value (i) of identifier
#[derive(Debug, Clone)]
pub struct SealLast {
    pub i: String, // identifier prefix (pre)
}

impl SealLast {
    pub fn new(i: String) -> Self {
        Self { i }
    }
}

pub enum Seal {
    SealLast(SealLast),
    SealEvent(SealEvent),
}

/// Attaches indexed signatures from sigers and/or cigars and/or wigers to KERI message data from serder
///
/// # Arguments
///
/// * `serder` - SerderKERI instance containing the event
/// * `sigers` - Optional list of Siger instances to create indexed signatures
/// * `seal` - Optional seal:
///     - If SealEvent: Use attachment group code TransIdxSigGroups plus attach
///       triple pre+snu+dig made from (i,s,d) of seal plus ControllerIdxSigs
///       plus attached indexed sigs in sigers
///     - If SealLast: Use attachment group code TransLastIdxSigGroups plus
///       attach triple pre made from (i) of seal plus ControllerIdxSigs
///       plus attached indexed sigs in sigers
///     - Else: Use ControllerIdxSigs plus attached indexed sigs in sigers
/// * `wigers` - Optional list of Siger instances of witness index signatures
/// * `cigars` - Optional list of Cigars instances of non-transferable non indexed
///   signatures from which to form receipt couples.
///   Each cigar.verfer.qb64 is pre of receiptor and cigar.qb64 is signature
/// * `pipelined` - If true, prepend pipelining count code to attachemnts
///   If false, do not prepend pipelining count code
///
/// # Returns
///
/// Bytearray containing the KERI event message
///
/// # Errors
///
/// Returns an error if there are no signatures attached or if there are invalid attachment sizes
pub fn messagize(
    serder: &SerderKERI,
    sigers: Option<&[Siger]>,
    seal: Option<Seal>,
    wigers: Option<&[Siger]>,
    cigars: Option<&[Cigar]>,
    pipelined: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut msg = serder.raw().to_vec(); // make copy of raw bytes
    let mut atc = Vec::new(); // attachment bytearray

    if sigers.is_none() && cigars.is_none() && wigers.is_none() {
        return Err("Missing attached signatures on message".into());
    }

    if let Some(sigers_slice) = sigers {
        if !sigers_slice.is_empty() {
            // Check if we have a seal
            if let Some(seal_any) = seal {
                // Try to downcast to SealEvent
                match seal_any {
                    Seal::SealLast(seal_last) => {
                        let counter = BaseCounter::from_code_and_count(
                            Some(ctr_dex_1_0::TRANS_LAST_IDX_SIG_GROUPS),
                            Some(1),
                            None,
                        )?;
                        atc.extend(counter.qb64b());

                        // Append seal data
                        atc.extend(seal_last.i.as_bytes());
                    }
                    Seal::SealEvent(seal_event) => {
                        let counter = BaseCounter::from_code_and_count(
                            Some(ctr_dex_1_0::TRANS_IDX_SIG_GROUPS),
                            Some(1),
                            None,
                        )?;
                        atc.extend(counter.qb64b());

                        // Append seal data
                        atc.extend(seal_event.i.as_bytes());
                        let seqner = Seqner::from_snh(&seal_event.s)?;
                        atc.extend(seqner.qb64b());
                        atc.extend(seal_event.d.as_bytes());
                    }
                }
            }

            // Add controller indexed signatures
            let counter = BaseCounter::from_code_and_count(
                Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS),
                Some(sigers_slice.len() as u64),
                None,
            )?;
            atc.extend(counter.qb64b());

            for siger in sigers_slice {
                atc.extend(siger.qb64b());
            }
        }
    }

    if let Some(wigers_slice) = wigers {
        if !wigers_slice.is_empty() {
            // Add witness indexed signatures
            let counter = BaseCounter::from_code_and_count(
                Some(ctr_dex_1_0::WITNESS_IDX_SIGS),
                Some(wigers_slice.len() as u64),
                None,
            )?;
            atc.extend(counter.qb64b());

            for wiger in wigers_slice {
                // Check if non-transferable
                if let Some(verfer) = &wiger.verfer() {
                    if !non_trans_dex::TUPLE.contains(&verfer.code()) {
                        return Err(format!(
                            "Attempt to use tranferable prefix={} for receipt.",
                            verfer.qb64()
                        )
                        .into());
                    }
                }
                atc.extend(wiger.qb64b());
            }
        }
    }

    if let Some(cigars_slice) = cigars {
        if !cigars_slice.is_empty() {
            // Add non-transferable receipt couples
            let counter = BaseCounter::from_code_and_count(
                Some(ctr_dex_1_0::NON_TRANS_RECEIPT_COUPLES),
                Some(cigars_slice.len() as u64),
                None,
            )?;
            atc.extend(counter.qb64b());

            for cigar in cigars_slice {
                // Check if non-transferable
                if !non_trans_dex::TUPLE.contains(&cigar.verfer().code()) {
                    return Err(format!(
                        "Attempt to use tranferable prefix={} for receipt.",
                        cigar.verfer().qb64()
                    )
                    .into());
                }

                // Append verfer and signature
                atc.extend(cigar.verfer().qb64b());
                atc.extend(cigar.qb64b());
            }
        }
    }

    if pipelined {
        // Check that attachments size is a multiple of 4 (integral quadlets)
        if atc.len() % 4 != 0 {
            return Err(format!(
                "Invalid attachments size={}, nonintegral quadlets.",
                atc.len()
            )
            .into());
        }

        // Add attachment group counter
        let counter = BaseCounter::from_code_and_count(
            Some(ctr_dex_1_0::ATTACHMENT_GROUP),
            Some((atc.len() / 4) as u64),
            None,
        )?;
        msg.extend(counter.qb64b());
    }

    // Add attachments to message
    msg.extend(atc);

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cesr::signing::{Salter, Sigmat};
    use crate::cesr::{mtr_dex, Matter};
    use crate::keri::app::keeping::{Keeper, Manager};
    use crate::keri::core::eventing::interact::InteractEventBuilder;
    use crate::keri::core::eventing::rotate::RotateEventBuilder;
    use crate::keri::core::serdering::SadValue;
    use crate::keri::db::dbing::LMDBer;
    use indexmap::IndexMap;
    use std::error::Error;
    use std::sync::Arc;

    #[test]
    fn test_messagize() -> Result<(), Box<dyn Error>> {
        // Create deterministic salter for testing
        let raw = b"0123456789abcdef";
        let salter = Salter::new(Some(raw), None, None)?;
        assert_eq!(salter.qb64b(), b"0AAwMTIzNDU2Nzg5YWJjZGVm");

        let lmdber = LMDBer::builder()
            .name("manager_ks")
            .reopen(true)
            .build()
            .expect("Failed to open manager database: {}");
        let keeper = Keeper::new(Arc::new(&lmdber)).expect("Failed to create manager database");
        let mut manager = Manager::new(keeper, None, None, None, None, Some(salter.qb64b()), None)?;
        // Test salty algorithm incept
        let (verfers, digers) = manager.incept(
            None,
            Some(1),
            None,
            None,
            Some(0),
            None,
            None,
            None,
            None,
            Some("C"),
            None,
            None,
            Some(true),
            None,
        )?;
        assert_eq!(verfers.len(), 1);
        assert_eq!(digers.len(), 0);
        assert_eq!(
            verfers[0].qb64b(),
            b"DOif48whAmpb_4kyksMcz57snMRIuX0bqN1FDe09AlRj"
        );

        // Create inception event
        let serder = InceptionEventBuilder::new(vec![verfers[0].qb64()])
            .with_code(mtr_dex::BLAKE3_256.to_string())
            .build()?;

        // Sign the serialized event
        let sigers: Vec<Siger> = manager
            .sign(
                serder.raw(),
                None,
                Some(verfers),
                None,
                None,
                None,
                None,
                None,
            )?
            .iter()
            .map(|sigmat| match sigmat {
                Sigmat::Indexed(siger) => siger.clone(),
                Sigmat::NonIndexed(_) => {
                    panic!("Unexpected non-indexed signature");
                }
            })
            .collect();

        // Test basic messagize with sigers
        let msg = messagize(&serder, Some(&sigers), None, None, None, false)?;

        // Expected output for basic case
        assert_eq!(
            String::from_utf8(msg.clone())?,
            concat!(
                r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ"#,
                r#"ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj"#,
                r#"JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b"#,
                r#"qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-AA"#,
                r#"BAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfP"#,
                r#"QQkQkxI862_XjyZLHyClVTLoD"#
            )
        );

        // Test with pipelined
        let msg = messagize(&serder, Some(&sigers), None, None, None, true)?;

        // Expected output for pipelined case
        assert_eq!(
            String::from_utf8(msg.clone())?,
            concat!(
                r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ"#,
                r#"ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj"#,
                r#"JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b"#,
                r#"qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA"#,
                r#"X-AABAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5"#,
                r#"lPfPQQkQkxI862_XjyZLHyClVTLoD"#
            )
        );

        // Test with SealEvent
        let seal = Seal::SealEvent(SealEvent::new(
            "DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI".to_string(),
            "0".to_string(),
            "EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z".to_string(),
        ));

        let msg = messagize(&serder, Some(&sigers), Some(seal), None, None, false)?;

        // Expected output with SealEvent
        assert_eq!(
            String::from_utf8(msg.clone())?,
            concat!(
                r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ"#,
                r#"ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj"#,
                r#"JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b"#,
                r#"qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-FA"#,
                r#"BDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAAAAAA"#,
                r#"AAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAB1DuEfnZZ"#,
                r#"6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_X"#,
                r#"jyZLHyClVTLoD"#
            )
        );

        // Test SealEvent with pipelined
        // Test with SealEvent
        let seal = Seal::SealEvent(SealEvent::new(
            "DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI".to_string(),
            "0".to_string(),
            "EMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z".to_string(),
        ));
        let msg = messagize(&serder, Some(&sigers), Some(seal), None, None, true)?;

        // Expected output for SealEvent with pipelined
        assert_eq!(
            String::from_utf8(msg.clone())?,
            concat!(
                r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ"#,
                r#"ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj"#,
                r#"JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b"#,
                r#"qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA"#,
                r#"0-FABDAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI0AAAAAAAAAAAAAA"#,
                r#"AAAAAAAAAEMuNWHss_H_kH4cG7Li1jn2DXfrEaqN7zhqTEhkeDZ2z-AABAAB1DuE"#,
                r#"fnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI8"#,
                r#"62_XjyZLHyClVTLoD"#
            )
        );

        let (verfers, digers) = manager.incept(
            None,
            Some(1),
            None,
            None,
            Some(0),
            None,
            None,
            None,
            None,
            Some("W"),
            None,
            None,
            Some(false),
            None,
        )?;

        // Test with wigers
        // First create a non-transferable signer
        let wigers: Vec<Siger> = manager
            .sign(
                serder.raw(),
                None,
                Some(verfers),
                None,
                None,
                None,
                None,
                None,
            )?
            .iter()
            .map(|sigmat| match sigmat {
                Sigmat::Indexed(siger) => siger.clone(),
                Sigmat::NonIndexed(_) => {
                    panic!("Unexpected non-indexed signature");
                }
            })
            .collect();

        let msg = messagize(&serder, None, None, Some(&wigers), None, false)?;

        // Expected output for wigers
        assert_eq!(
            String::from_utf8(msg.clone())?,
            concat!(
                r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ"#,
                r#"ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj"#,
                r#"JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b"#,
                r#"qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-BA"#,
                r#"BAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj"#,
                r#"20VJYa4947ZMVrOxKhzI6EqUH"#
            )
        );

        // Test wigers with pipelined
        let msg = messagize(&serder, None, None, Some(&wigers), None, true)?;

        // Expected output for wigers with pipelined
        assert_eq!(
            String::from_utf8(msg.clone())?,
            concat!(
                r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ"#,
                r#"ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj"#,
                r#"JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b"#,
                r#"qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA"#,
                r#"X-BABAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eo"#,
                r#"NhEj20VJYa4947ZMVrOxKhzI6EqUH"#
            )
        );

        // Test with cigars
        // Create a non-transferable signer for cigars (non-indexed signatures)
        let (verfers, digers) = manager.incept(
            None,
            Some(1),
            None,
            None,
            Some(0),
            None,
            None,
            None,
            None,
            Some("R"),
            None,
            None,
            Some(false),
            None,
        )?;

        let cigars: Vec<Cigar> = manager
            .sign(
                serder.raw(),
                None,
                Some(verfers),
                Some(false),
                None,
                None,
                None,
                None,
            )?
            .iter()
            .map(|sigmat| match sigmat {
                Sigmat::Indexed(siger) => {
                    panic!("Unexpected non-indexed signature");
                }
                Sigmat::NonIndexed(cigar) => cigar.clone(),
            })
            .collect();
        let msg = messagize(&serder, None, None, None, Some(&cigars), false)?;

        // Expected output for cigars
        assert_eq!(
            String::from_utf8(msg.clone())?,
            concat!(
                r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ"#,
                r#"ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj"#,
                r#"JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b"#,
                r#"qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-CA"#,
                r#"BBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFi"#,
                r#"DF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVw"#,
                r#"g_TwF"#
            )
        );

        // Test cigars with pipelined
        let msg = messagize(&serder, None, None, None, Some(&cigars), true)?;

        // Expected output for cigars with pipelined
        assert_eq!(
            String::from_utf8(msg.clone())?,
            concat!(
                r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ"#,
                r#"ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj"#,
                r#"JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b"#,
                r#"qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA"#,
                r#"i-CABBJjH1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgG"#,
                r#"FtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko"#,
                r#"5EVwg_TwF"#
            )
        );

        // Test with wigers and cigars
        let msg = messagize(&serder, None, None, Some(&wigers), Some(&cigars), false)?;

        // Expected output for wigers and cigars
        assert_eq!(
            String::from_utf8(msg.clone())?,
            concat!(
                r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ"#,
                r#"ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj"#,
                r#"JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b"#,
                r#"qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-BA"#,
                r#"BAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj"#,
                r#"20VJYa4947ZMVrOxKhzI6EqUH-CABBJjH1MCDssEZMnORskF34AwOFDgDL47513G"#,
                r#"ivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa0rUV"#,
                r#"X2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF"#
            )
        );

        // Test with wigers and cigars and pipelined
        let msg = messagize(&serder, None, None, Some(&wigers), Some(&cigars), true)?;

        // Expected output for wigers and cigars with pipelined
        assert_eq!(
            String::from_utf8(msg.clone())?,
            concat!(
                r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ"#,
                r#"ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj"#,
                r#"JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b"#,
                r#"qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VA"#,
                r#"5-BABAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_JuO4RioH1NUTtzTuV1bbuB7eo"#,
                r#"NhEj20VJYa4947ZMVrOxKhzI6EqUH-CABBJjH1MCDssEZMnORskF34AwOFDgDL47"#,
                r#"513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas-6Bzvj0xtOfbsh31jjtshcEa"#,
                r#"0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF"#
            )
        );

        // Test with sigers, wigers, and cigars
        let msg = messagize(
            &serder,
            Some(&sigers),
            None,
            Some(&wigers),
            Some(&cigars),
            false,
        )?;

        // Expected output for sigers, wigers, and cigars
        assert_eq!(
            String::from_utf8(msg.clone())?,
            concat!(
                r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ"#,
                r#"ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj"#,
                r#"JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b"#,
                r#"qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-AA"#,
                r#"BAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfP"#,
                r#"QQkQkxI862_XjyZLHyClVTLoD-BABAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyxs7_J"#,
                r#"uO4RioH1NUTtzTuV1bbuB7eoNhEj20VJYa4947ZMVrOxKhzI6EqUH-CABBJjH1MC"#,
                r#"DssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7QoVas"#,
                r#"-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF"#
            )
        );

        // Test with sigers, wigers, cigars and pipelined
        let msg = messagize(
            &serder,
            Some(&sigers),
            None,
            Some(&wigers),
            Some(&cigars),
            true,
        )?;

        // Expected output for sigers, wigers, cigars with pipelined
        assert_eq!(
            String::from_utf8(msg)?,
            concat!(
                r#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EFyzzg2Mp5A3ecChc6AhSLTQ"#,
                r#"ssBZAmNvPnGxjJyHxl4F","i":"EFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxj"#,
                r#"JyHxl4F","s":"0","kt":"1","k":["DOif48whAmpb_4kyksMcz57snMRIuX0b"#,
                r#"qN1FDe09AlRj"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VB"#,
                r#"Q-AABAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5"#,
                r#"lPfPQQkQkxI862_XjyZLHyClVTLoD-BABAABtOhjlKo8WhJQ3EXMIMaQ_IH6yeyx"#,
                r#"s7_JuO4RioH1NUTtzTuV1bbuB7eoNhEj20VJYa4947ZMVrOxKhzI6EqUH-CABBJj"#,
                r#"H1MCDssEZMnORskF34AwOFDgDL47513GivRvd_QKz0BDwWrxO8RItpgGFtFiDF7Q"#,
                r#"oVas-6Bzvj0xtOfbsh31jjtshcEa0rUVX2xsyyH1US2fBWe7FNpn6xko5EVwg_TwF"#
            )
        );

        Ok(())
    }

    #[test]
    fn test_full_kel() -> Result<(), Box<dyn Error>> {
        // Create deterministic salter for testing
        let raw = b"abcdef0123456789";
        let salter = Salter::new(Some(raw), None, None)?;
        assert_eq!(salter.qb64(), "0ABhYmNkZWYwMTIzNDU2Nzg5");

        let lmdber = LMDBer::builder()
            .name("manager_ks")
            .reopen(true)
            .build()
            .expect("Failed to open manager database: {}");
        let keeper = Keeper::new(Arc::new(&lmdber)).expect("Failed to create manager database");
        let mut manager = Manager::new(keeper, None, None, None, None, Some(salter.qb64b()), None)?;
        // Test salty algorithm incept
        let (verfers, digers) = manager.incept(
            None,
            Some(1),
            None,
            None,
            Some(1),
            None,
            None,
            None,
            None,
            Some("C"),
            None,
            None,
            Some(true),
            None,
        )?;
        assert_eq!(verfers.len(), 1);
        assert_eq!(digers.len(), 1);
        assert_eq!(
            verfers[0].qb64(),
            "DCjMCQ638m293JGMIjU7ch0bqmaU6-v4AK_wBf6jl4OX"
        );
        assert_eq!(
            digers[0].qb64(),
            "EEyU3aS2N1JrMq5kDQ4tZ_5PBTRD8ISUx3WUsuj0rU3-"
        );

        // Create inception event
        let serder = InceptionEventBuilder::new(vec![verfers[0].qb64()])
            .with_code(mtr_dex::BLAKE3_256.to_string())
            .with_ndigs(vec![digers[0].qb64()])
            .build()?;

        let oldspre = verfers[0].qb64b();
        let spre = serder.preb().unwrap();
        manager.move_prefix(&oldspre, &spre)?;

        // Sign the serialized event
        let sigers: Vec<Siger> = manager
            .sign(
                serder.raw(),
                None,
                Some(verfers),
                None,
                None,
                None,
                None,
                None,
            )?
            .iter()
            .map(|sigmat| match sigmat {
                Sigmat::Indexed(siger) => siger.clone(),
                Sigmat::NonIndexed(_) => {
                    panic!("Unexpected non-indexed signature");
                }
            })
            .collect();

        // Lets collect the full KEL
        let mut kel = String::new();

        // Test basic messagize with sigers
        let msg = messagize(&serder, Some(&sigers), None, None, None, false)?;
        kel.push_str(&String::from_utf8(msg.clone())?);

        assert_eq!(
            String::from_utf8(msg)?,
            concat!(
                r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EPXgQxGLRPBzBR84e6hZ_SY1l5-WJU8b_n8ibASNDfKM","#,
                r#""i":"EPXgQxGLRPBzBR84e6hZ_SY1l5-WJU8b_n8ibASNDfKM","s":"0","kt":"1","k":["#,
                r#""DCjMCQ638m293JGMIjU7ch0bqmaU6-v4AK_wBf6jl4OX"],"nt":"1","n":["EEyU3aS2N1JrMq5k"#,
                r#"DQ4tZ_5PBTRD8ISUx3WUsuj0rU3-"],"bt":"0","b":[],"c":[],"a":[]}-AABAABGkiiW6C8_"#,
                r#"TTeT0XuWuxjrQ4Fp7hkurrP2oqYFBKMTYcoZDa5_ekzjQDOMX6cCZVeUBbbFnB0D7EX36vz385sM"#
            )
        );

        let (verfers, digers) = manager.rotate(
            &serder.preb().unwrap(),
            None,
            Some(1),
            None,
            None,
            Some(true),
            Some(false),
            Some(false),
        )?;
        assert_eq!(verfers.len(), 1);
        assert_eq!(digers.len(), 1);
        assert_eq!(
            verfers[0].qb64(),
            "DDxkQL-tXDKwAKPnVpmKgmeIP5GAa4nSI6pWFbuYc8Ye"
        );
        assert_eq!(
            digers[0].qb64(),
            "EBIjhA2t-Sfm29atirPEG-VD9ouVzy7i7PrFslG6D7tm"
        );

        let rserder = RotateEventBuilder::new(
            serder.pre().unwrap(),
            vec![verfers[0].qb64()],
            serder.said().unwrap().to_string(),
        )
        .with_ndigs(vec![digers[0].qb64()])
        .build()?;

        // Sign the serialized event
        let rsigers: Vec<Siger> = manager
            .sign(
                rserder.raw(),
                None,
                Some(verfers.clone()),
                None,
                None,
                None,
                None,
                None,
            )?
            .iter()
            .map(|sigmat| match sigmat {
                Sigmat::Indexed(siger) => siger.clone(),
                Sigmat::NonIndexed(_) => {
                    panic!("Unexpected non-indexed signature");
                }
            })
            .collect();

        // Test rotation with messagize with sigers
        let msg = messagize(&rserder, Some(&rsigers), None, None, None, false)?;
        kel.push_str(&String::from_utf8(msg.clone())?);
        assert_eq!(
            String::from_utf8(msg)?,
            concat!(
                r#"{"v":"KERI10JSON000160_","t":"rot","d":"EFFvfdKjytGurVS52KzF5NefoQkVJp9w3vDb5is9mEzP","#,
                r#""i":"EPXgQxGLRPBzBR84e6hZ_SY1l5-WJU8b_n8ibASNDfKM","s":"1","p":"EPXgQxGLRPBzBR84e6hZ_"#,
                r#"SY1l5-WJU8b_n8ibASNDfKM","kt":"1","k":["DDxkQL-tXDKwAKPnVpmKgmeIP5GAa4nSI6pWFbuYc8Ye"],"#,
                r#""nt":"1","n":["EBIjhA2t-Sfm29atirPEG-VD9ouVzy7i7PrFslG6D7tm"],"bt":"0","br":[],"ba":[],"#,
                r#""a":[]}-AABAADKqAHzC9bQ6VZy9HP5uG7-YhFDJsPGvCYj8BkX3z8GWIpcNdeXE4t7XRXxddn6r19uTxsBs-"#,
                r#"zN_-41rgzMM68M"#
            )
        );

        // Create data attachments
        let mut data_map1 = IndexMap::new();
        data_map1.insert(
            "i".to_string(),
            SadValue::String("EbAwspDmOlHDUjGZ8m9JGQ4r7Knt5gu4KBNt0JSL2ZoI".to_string()),
        );
        data_map1.insert("s".to_string(), SadValue::String("3".to_string()));
        data_map1.insert(
            "d".to_string(),
            SadValue::String("EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-DpRXs".to_string()),
        );
        let data = vec![SadValue::from(SadValue::Object(data_map1))];

        let xserder =
            InteractEventBuilder::new(serder.pre().unwrap(), rserder.said().unwrap().to_string())
                .with_sn(2)
                .with_data_list(data)
                .build()?;

        // Sign the serialized event
        let xsigers: Vec<Siger> = manager
            .sign(
                xserder.raw(),
                None,
                Some(verfers),
                None,
                None,
                None,
                None,
                None,
            )?
            .iter()
            .map(|sigmat| match sigmat {
                Sigmat::Indexed(siger) => siger.clone(),
                Sigmat::NonIndexed(_) => {
                    panic!("Unexpected non-indexed signature");
                }
            })
            .collect();
        let msg = messagize(&xserder, Some(&xsigers), None, None, None, false)?;
        kel.push_str(&String::from_utf8(msg.clone())?);
        assert_eq!(
            String::from_utf8(msg)?,
            concat!(
                r#"{"v":"KERI10JSON00013a_","t":"ixn","d":"EMljYBNn3JU_oD8O0_JmQ1Q7w3yFnCON9lauFHnDmNju","#,
                r#""i":"EPXgQxGLRPBzBR84e6hZ_SY1l5-WJU8b_n8ibASNDfKM","s":"2","p":"EFFvfdKjytGurVS52KzF5"#,
                r#"NefoQkVJp9w3vDb5is9mEzP","a":[{"i":"EbAwspDmOlHDUjGZ8m9JGQ4r7Knt5gu4KBNt0JSL2ZoI","s":"#,
                r#""3","d":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-DpRXs"}]}-AABAAAg0JyLoHFC2vezhTm6jz_"#,
                r#"BxbmSbSsvqxzeM8sP9fPekAFCKnlH-tsL_0SYmhA5HDXLcmQ4yWa0oWo4w4sYe0sP"#
            )
        );

        let (verfers, digers) = manager.rotate(
            &serder.preb().unwrap(),
            None,
            Some(1),
            None,
            None,
            Some(true),
            Some(false),
            Some(false),
        )?;
        assert_eq!(verfers.len(), 1);
        assert_eq!(digers.len(), 1);
        assert_eq!(
            verfers[0].qb64(),
            "DNFcsn7EiJemcWD_6bMOdeYUU1j2dC98WCCGjN7PxCIp"
        );
        assert_eq!(
            digers[0].qb64(),
            "EAu_UWkr40QDQWScisiLnv5rCJc5unxnAhu33V1RzzpA"
        );

        let rserder = RotateEventBuilder::new(
            serder.pre().unwrap(),
            vec![verfers[0].qb64()],
            xserder.said().unwrap().to_string(),
        )
        .with_sn(3)
        .with_ndigs(vec![digers[0].qb64()])
        .build()?;

        // Sign the serialized event
        let rsigers: Vec<Siger> = manager
            .sign(
                rserder.raw(),
                None,
                Some(verfers),
                None,
                None,
                None,
                None,
                None,
            )?
            .iter()
            .map(|sigmat| match sigmat {
                Sigmat::Indexed(siger) => siger.clone(),
                Sigmat::NonIndexed(_) => {
                    panic!("Unexpected non-indexed signature");
                }
            })
            .collect();

        // Test rotation with messagize with sigers
        let msg = messagize(&rserder, Some(&rsigers), None, None, None, false)?;
        kel.push_str(&String::from_utf8(msg.clone())?);
        assert_eq!(
            String::from_utf8(msg)?,
            concat!(
                r#"{"v":"KERI10JSON000160_","t":"rot","d":"EGC9ReDqCudaBI65eEmn2M52rr3YLb0j1j3PR0SAvSz9","#,
                r#""i":"EPXgQxGLRPBzBR84e6hZ_SY1l5-WJU8b_n8ibASNDfKM","s":"3","p":"EMljYBNn3JU_oD8O0_JmQ1Q7"#,
                r#"w3yFnCON9lauFHnDmNju","kt":"1","k":["DNFcsn7EiJemcWD_6bMOdeYUU1j2dC98WCCGjN7PxCIp"],"#,
                r#""nt":"1","n":["EAu_UWkr40QDQWScisiLnv5rCJc5unxnAhu33V1RzzpA"],"bt":"0","br":[],"ba":[],"#,
                r#""a":[]}-AABAACe5_Be6a0cYFts3p5clD7X2RCjkWGQVmKvLjr8ONN9azBqPRQGMj6B7eRwHFQ-AdC98PNA"#,
                r#"niDuFv4BGK8GsvoE"#
            )
        );

        println!("{}", kel);

        Ok(())
    }
}
