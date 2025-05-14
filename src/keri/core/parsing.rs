use crate::cesr::cigar::Cigar;
use crate::cesr::counting::{ctr_dex_1_0, BaseCounter, Counter};
use crate::cesr::dater::Dater;
use crate::cesr::indexing::siger::Siger;
use crate::cesr::pather::Pather;
use crate::cesr::prefixer::Prefixer;
use crate::cesr::saider::Saider;
use crate::cesr::seqner::Seqner;
use crate::cesr::texter::Texter;
use crate::cesr::verfer::Verfer;
use crate::cesr::COLDS;
use crate::cesr::{sniff, Parsable, Versionage, VRSN_1_0};
use crate::errors::MatterError;
use crate::keri::core::serdering::{Serder, SerderACDC, SerderKERI, Serdery};
use crate::keri::{Ilk, KERIError};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt};
use crate::keri::core::eventing::Kevery;

/// Trans Indexed Sig Groups
#[derive(Debug, Clone)]
pub struct Tsgs {
    prefixer: Prefixer,
    seqner: Seqner,
    saider: Saider,
    sigers: Vec<Siger>,
}

#[derive(Debug, Clone)]
pub struct Trqs {
    prefixer: Prefixer,
    seqner: Seqner,
    saider: Saider,
    siger: Siger,
}

#[derive(Debug, Clone)]
pub struct Trrs {
    prefixer: Prefixer,
    seqner: Seqner,
}

#[derive(Debug, Clone)]
pub struct Ssgs {
    prefixer: Prefixer,
    sigers: Vec<Siger>,
}

#[derive(Debug, Clone)]
pub struct Frcs {
    seqner: Seqner,
    dater: Dater,
}

#[derive(Debug, Clone)]
pub struct Ssts {
    prefixer: Prefixer,
    seqner: Seqner,
    saider: Saider,
}

#[derive(Debug, Clone)]
pub struct Sscs {
    seqner: Seqner,
    saider: Saider,
}

/// Trans Indexed Sig Groups
#[derive(Debug, Clone)]
pub struct SadTsgs {
    path: Pather,
    prefixer: Prefixer,
    seqner: Seqner,
    saider: Saider,
    sigers: Vec<Siger>,
}

#[derive(Debug, Clone)]
pub struct SadSigers {
    path: Pather,
    sigers: Vec<Siger>,
}

#[derive(Debug, Clone)]
pub struct SadCigars {
    path: Pather,
    cigar: Cigar,
}

/// Enum to represent the different types of SadPathGroups
pub enum SadPathGroup {
    TransIdxSig(SadTsgs),
    ControllerIdxSig(SadSigers),
    NonTransReceipt(SadCigars),
}

/// Represents all possible parsed messages from a KERI stream that can be processed
/// by Kevery, Tevery, Exchanger, Revery, or Verifier
pub enum Message {
    /// Identifier key event messages
    KeyEvent {
        serder: Box<SerderKERI>,
        sigers: Option<Vec<Siger>>,
        wigers: Option<Vec<Siger>>,
        delseqner: Option<Seqner>,
        delsaider: Option<Saider>,
        firner: Option<Seqner>,
        dater: Option<Dater>,
        cigars: Option<Vec<Cigar>>, // For process attached receipt couples
        trqs: Option<Vec<Trqs>>,    // For process attached receipt quadruples
        local: Option<bool>,
    },

    /// Non-transferable receipt messages
    Receipt {
        serder: Box<SerderKERI>,
        cigars: Vec<Cigar>,
        local: Option<bool>,
    },

    /// Witness receipt messages
    WitnessReceipt {
        serder: Box<SerderKERI>,
        wigers: Vec<Siger>,
        local: Option<bool>,
    },

    /// Transferable receipt messages
    ReceiptTrans {
        serder: Box<dyn Serder>,
        tsgs: Vec<Tsgs>,
        local: Option<bool>,
    },

    /// Query messages for Kevery or Tevery
    Query {
        serder: Box<SerderKERI>,
        source: Option<Prefixer>,
        sigers: Option<Vec<Siger>>,
        cigar: Option<Vec<Cigar>>,
    },

    /// Reply messages for Revery with non-transferable signatures
    ReplyNonTrans {
        serder: Box<dyn Serder>,
        cigars: Vec<Cigar>,
    },

    /// Reply messages for Revery with transferable signatures
    ReplyTrans {
        serder: Box<dyn Serder>,
        tsgs: Vec<Tsgs>,
    },

    /// Event messages for Exchanger with non-transferable signatures
    ExchangeEventNonTrans {
        serder: Box<dyn Serder>,
        cigars: Vec<Cigar>,
        pathed: Option<Vec<Vec<u8>>>,
        essrs: Option<Vec<Texter>>,
    },

    /// Event messages for Exchanger with transferable signatures
    ExchangeEventTrans {
        serder: Box<dyn Serder>,
        tsgs: Vec<Tsgs>,
        pathed: Option<Vec<Vec<u8>>>,
        essrs: Option<Vec<Texter>>,
    },

    /// TEL events for Tevery
    TELEvent {
        serder: Box<dyn Serder>,
        seqner: Option<Seqner>,
        saider: Option<Saider>,
        wigers: Option<Vec<Siger>>,
    },

    /// Credential messages for Verifier
    Credential {
        creder: Box<dyn Serder>,
        prefixer: Option<Prefixer>,
        seqner: Option<Seqner>,
        saider: Option<Saider>,
    },
}

// Implementation with helper methods
impl Message {
    /// Determines if the message is local
    pub fn is_local(&self) -> bool {
        match self {
            Message::KeyEvent { local, .. } => local.unwrap_or(false),
            Message::Receipt { local, .. } => local.unwrap_or(false),
            Message::WitnessReceipt { local, .. } => local.unwrap_or(false),
            Message::ReceiptTrans { local, .. } => local.unwrap_or(false),
            _ => false,
        }
    }
}
// Traits for message handlers
#[async_trait::async_trait]
pub trait MessageHandler: Send + Sync {
    async fn handle(&self, msg: Message) -> Result<(), KERIError>;
}

pub struct Parser<'a, R> {
    reader: R,
    buffer: Vec<u8>,
    framed: bool,
    pipeline: bool,
    handlers: Handlers<'a>,
    serdery: Serdery,
}
pub struct Handlers<'a> {
    pub kevery: Arc<Mutex<Kevery<'a>>>,
    pub tevery: Arc<dyn MessageHandler>,
    pub exchanger: Arc<dyn MessageHandler>,
    pub revery: Arc<dyn MessageHandler>,
    pub verifier: Arc<dyn MessageHandler>,
    pub local: bool,
}

impl<'a, R: AsyncRead + Unpin + Send> Parser<'a, R> {
    pub fn new(reader: R, framed: bool, pipeline: bool, handlers: Handlers<'a>) -> Self {
        Self {
            reader,
            buffer: Vec::new(),
            framed,
            pipeline,
            handlers,
            serdery: Serdery::new(),
        }
    }

    pub async fn parse_stream(&mut self, once: Option<bool>) -> Result<(), KERIError> {
        loop {
            // Read data asynchronously into buffer
            let mut chunk = vec![0u8; 4096];

            let n = self.reader.read(&mut chunk).await?;
            if n == 0 {
                break; // EOF
            }
            self.buffer.extend_from_slice(&chunk[..n]);

            // Process buffer into messages
            loop {
                let (msg, _) = self.try_parse_message()?;
                self.dispatch_message(msg).await?;
                if self.buffer.len() == 0 {
                    if once.unwrap_or(false) {
                        return Ok(());
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    fn try_parse_message(&mut self) -> Result<(Message, usize), MatterError> {
        let serder = self
            .serdery
            .reap(self.buffer.as_slice(), "-AAAA", &VRSN_1_0, None, None)
            .map_err(|_| MatterError::EncodingError("Invalid UTF-8 in count chars".to_string()))?;
        let serder_size = serder.size();
        self.buffer.drain(..serder_size);

        match sniff(self.buffer.as_slice()) {
            Ok(cold) => {
                if cold == COLDS.msg {
                    return Err(MatterError::NeedMoreDataError("".to_string()));
                }
                let mut attachment_size = 0;

                // Initialize collections for different attachment types
                let mut sigers: Vec<Siger> = Vec::new();
                let mut wigers: Vec<Siger> = Vec::new();
                let mut cigars: Vec<Cigar> = Vec::new();
                let mut trqs: Vec<Trqs> = Vec::new();
                let mut tsgs: Vec<Tsgs> = Vec::new();
                let mut ssgs: Vec<Ssgs> = Vec::new();
                let mut frcs: Vec<Frcs> = Vec::new();
                let mut sscs: Vec<Sscs> = Vec::new();
                let mut ssts: Vec<Ssts> = Vec::new();
                let mut sadtsgs: Vec<SadTsgs> = Vec::new();
                let mut sadsigs: Vec<SadSigers> = Vec::new();
                let mut sadcigs: Vec<SadCigars> = Vec::new();
                let mut pathed: Vec<Vec<u8>> = Vec::new();
                let mut essrs: Vec<Texter> = Vec::new();

                // Check if we have more data in the buffer for attachments
                if !self.buffer.is_empty() {
                    // Determine the stream state (txt or bny)
                    let mut cold = sniff(&self.buffer)?;

                    // Not a new message so process attachments
                    if cold != COLDS.msg {
                        let mut pipelined = false;

                        // Extract counter at front of attachments
                        match self._extractor::<BaseCounter>(cold, false, &VRSN_1_0) {
                            Ok(ctr) => {
                                // Check if this is a pipelined attachment group
                                if ctr.code() == ctr_dex_1_0::ATTACHMENT_GROUP {
                                    pipelined = true;

                                    // Compute pipelined attached group size based on txt or bny
                                    let pags = if cold == COLDS.txt {
                                        ctr.count() * 4
                                    } else {
                                        ctr.count() * 3
                                    };

                                    // Make sure we have enough data for the full pipelined group
                                    if self.buffer.len() < pags as usize {
                                        return Err(MatterError::NeedMoreDataError("".to_string()));
                                    }

                                    // Extract counter from the pipelined data
                                    match self._extractor::<BaseCounter>(cold, pipelined, &VRSN_1_0)
                                    {
                                        Ok(extracted_ctr) => {
                                            self.process_attachments(
                                                &extracted_ctr,
                                                cold,
                                                pipelined,
                                                &mut sigers,
                                                &mut wigers,
                                                &mut cigars,
                                                &mut trqs,
                                                &mut tsgs,
                                                &mut ssgs,
                                                &mut frcs,
                                                &mut sscs,
                                                &mut ssts,
                                                &mut sadtsgs,
                                                &mut sadsigs,
                                                &mut sadcigs,
                                                &mut pathed,
                                                &mut essrs,
                                            )?;
                                        }
                                        Err(e) => return Err(e),
                                    }
                                } else {
                                    // Not pipelined, process attachments iteratively
                                    let mut current_ctr = ctr;
                                    loop {
                                        // Process the current counter
                                        self.process_attachments(
                                            &current_ctr,
                                            cold,
                                            pipelined,
                                            &mut sigers,
                                            &mut wigers,
                                            &mut cigars,
                                            &mut trqs,
                                            &mut tsgs,
                                            &mut ssgs,
                                            &mut frcs,
                                            &mut sscs,
                                            &mut ssts,
                                            &mut sadtsgs,
                                            &mut sadsigs,
                                            &mut sadcigs,
                                            &mut pathed,
                                            &mut essrs,
                                        )?;

                                        // Check if we're at the end or should continue
                                        if pipelined {
                                            if self.buffer.is_empty() {
                                                break; // End of pipelined group frame
                                            }
                                        } else if self.framed {
                                            if self.buffer.is_empty() {
                                                break; // End of frame
                                            }
                                            let new_cold = sniff(&self.buffer)?;
                                            if new_cold == COLDS.msg {
                                                break; // New message, attachments done
                                            }
                                            cold = new_cold;
                                        } else {
                                            // Process until next message
                                            if self.buffer.is_empty() {
                                                return Err(MatterError::NeedMoreDataError(
                                                    "Need more data".to_string(),
                                                ));
                                            }
                                            let new_cold = sniff(&self.buffer)?;
                                            if new_cold == COLDS.msg {
                                                break; // New message, attachments done
                                            }
                                            cold = new_cold;
                                        }

                                        // Extract the next counter
                                        match self._extractor::<BaseCounter>(cold, false, &VRSN_1_0)
                                        {
                                            Ok(next_ctr) => {
                                                current_ctr = next_ctr;
                                            }
                                            Err(e) => return Err(e),
                                        }
                                    }
                                }
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }

                attachment_size += 0;

                // Now construct appropriate Message variant based on serder and attachments
                let msg = self.process_message(
                    serder,
                    sigers,
                    wigers,
                    cigars,
                    trqs,
                    tsgs,
                    ssgs,
                    sscs,
                    frcs,
                    ssts,
                    pathed,
                    sadtsgs,
                    sadcigs,
                    essrs,
                    self.handlers.local,
                )?;

                Ok((msg, serder_size + attachment_size))
            }
            Err(_) => Err(MatterError::Shortage("Short on the sniff".to_string())),
        }
    }

    // Helper method to process a single counter and its data
    fn process_attachments(
        &mut self,
        ctr: &BaseCounter,
        cold: &str,
        pipelined: bool,
        sigers: &mut Vec<Siger>,
        wigers: &mut Vec<Siger>,
        cigars: &mut Vec<Cigar>,
        trqs: &mut Vec<Trqs>,
        tsgs: &mut Vec<Tsgs>,
        ssgs: &mut Vec<Ssgs>,
        frcs: &mut Vec<Frcs>,
        sscs: &mut Vec<Sscs>,
        ssts: &mut Vec<Ssts>,
        sadtsgs: &mut Vec<SadTsgs>,
        sadsigs: &mut Vec<SadSigers>,
        sadcigs: &mut Vec<SadCigars>,
        pathed: &mut Vec<Vec<u8>>,
        essrs: &mut Vec<Texter>,
    ) -> Result<(), MatterError> {
        match ctr.code() {
            ctr_dex_1_0::CONTROLLER_IDX_SIGS => {
                for _ in 0..ctr.count() {
                    match self._extractor::<Siger>(cold, pipelined, &VRSN_1_0) {
                        Ok(siger) => sigers.push(siger),
                        Err(e) => return Err(e),
                    }
                }
            }

            ctr_dex_1_0::WITNESS_IDX_SIGS => {
                for _ in 0..ctr.count() {
                    match self._extractor::<Siger>(cold, pipelined, &VRSN_1_0) {
                        Ok(wiger) => wigers.push(wiger),
                        Err(e) => return Err(e),
                    }
                }
            }

            ctr_dex_1_0::NON_TRANS_RECEIPT_COUPLES => {
                // Extract receipt couplets into cigars
                match self.non_trans_receipt_couples(ctr, cold, pipelined, &VRSN_1_0) {
                    Ok(extracted_cigars) => cigars.extend(extracted_cigars),
                    Err(e) => return Err(e),
                }
            }

            ctr_dex_1_0::NON_TRANS_RECEIPT_COUPLES => {
                for _ in 0..ctr.count() {
                    // Extract each attached quadruple
                    let prefixer = match self._extractor::<Prefixer>(cold, pipelined, &VRSN_1_0) {
                        Ok(p) => p,
                        Err(e) => return Err(e),
                    };

                    let seqner = match self._extractor::<Seqner>(cold, pipelined, &VRSN_1_0) {
                        Ok(s) => s,
                        Err(e) => return Err(e),
                    };

                    let saider = match self._extractor::<Saider>(cold, pipelined, &VRSN_1_0) {
                        Ok(s) => s,
                        Err(e) => return Err(e),
                    };

                    let siger = match self._extractor::<Siger>(cold, pipelined, &VRSN_1_0) {
                        Ok(s) => s,
                        Err(e) => return Err(e),
                    };

                    trqs.push(Trqs {
                        prefixer,
                        seqner,
                        saider,
                        siger,
                    });
                }
            }

            ctr_dex_1_0::TRANS_IDX_SIG_GROUPS => {
                match self.trans_idx_sig_groups(ctr, cold, pipelined, &VRSN_1_0) {
                    Ok(extracted_tsgs) => tsgs.extend(extracted_tsgs),
                    Err(e) => return Err(e),
                }
            }

            ctr_dex_1_0::TRANS_LAST_IDX_SIG_GROUPS => {
                for _ in 0..ctr.count() {
                    let prefixer = match self._extractor::<Prefixer>(cold, pipelined, &VRSN_1_0) {
                        Ok(p) => p,
                        Err(e) => return Err(e),
                    };

                    let ictr = match self._extractor::<BaseCounter>(cold, pipelined, &VRSN_1_0) {
                        Ok(c) => c,
                        Err(e) => return Err(e),
                    };

                    if ictr.code() != ctr_dex_1_0::CONTROLLER_IDX_SIGS {
                        return Err(MatterError::UnexpectedCountCodeError(format!(
                            "Wrong count code={}. Expected code={}.",
                            ictr.code(),
                            ctr_dex_1_0::CONTROLLER_IDX_SIGS
                        )));
                    }

                    let mut isigers = Vec::new();
                    for _ in 0..ictr.count() {
                        match self._extractor::<Siger>(cold, pipelined, &VRSN_1_0) {
                            Ok(isiger) => isigers.push(isiger),
                            Err(e) => return Err(e),
                        }
                    }

                    ssgs.push(Ssgs {
                        prefixer,
                        sigers: isigers,
                    });
                }
            }

            ctr_dex_1_0::FIRST_SEEN_REPLAY_COUPLES => {
                for _ in 0..ctr.count() {
                    let firner = match self._extractor::<Seqner>(cold, pipelined, &VRSN_1_0) {
                        Ok(f) => f,
                        Err(e) => return Err(e),
                    };

                    let dater = match self._extractor::<Dater>(cold, pipelined, &VRSN_1_0) {
                        Ok(d) => d,
                        Err(e) => return Err(e),
                    };

                    frcs.push(Frcs {
                        seqner: firner,
                        dater,
                    });
                }
            }

            ctr_dex_1_0::SEAL_SOURCE_COUPLES => {
                for _ in 0..ctr.count() {
                    let seqner = match self._extractor::<Seqner>(cold, pipelined, &VRSN_1_0) {
                        Ok(s) => s,
                        Err(e) => return Err(e),
                    };

                    let saider = match self._extractor::<Saider>(cold, pipelined, &VRSN_1_0) {
                        Ok(s) => s,
                        Err(e) => return Err(e),
                    };

                    sscs.push(Sscs { seqner, saider });
                }
            }

            ctr_dex_1_0::SEAL_SOURCE_TRIPLES => {
                for _ in 0..ctr.count() {
                    let prefixer = match self._extractor::<Prefixer>(cold, pipelined, &VRSN_1_0) {
                        Ok(p) => p,
                        Err(e) => return Err(e),
                    };

                    let seqner = match self._extractor::<Seqner>(cold, pipelined, &VRSN_1_0) {
                        Ok(s) => s,
                        Err(e) => return Err(e),
                    };

                    let saider = match self._extractor::<Saider>(cold, pipelined, &VRSN_1_0) {
                        Ok(s) => s,
                        Err(e) => return Err(e),
                    };

                    ssts.push(Ssts {
                        prefixer,
                        seqner,
                        saider,
                    });
                }
            }

            ctr_dex_1_0::SAD_PATH_SIG_GROUPS => {
                let path = match self._extractor::<Pather>(cold, pipelined, &VRSN_1_0) {
                    Ok(p) => p,
                    Err(e) => return Err(e),
                };

                for _ in 0..ctr.count() {
                    let ictr = match self._extractor::<BaseCounter>(cold, pipelined, &VRSN_1_0) {
                        Ok(c) => c,
                        Err(e) => return Err(e),
                    };

                    match self.sad_path_sig_group(&ictr, Some(&path), cold, pipelined, &VRSN_1_0) {
                        Ok(groups) => {
                            for group in groups {
                                match group {
                                    SadPathGroup::TransIdxSig(sadtsg) => {
                                        sadtsgs.push(sadtsg);
                                    }
                                    SadPathGroup::ControllerIdxSig(sadsiger) => {
                                        sadsigs.push(sadsiger);
                                    }
                                    SadPathGroup::NonTransReceipt(sadcigar) => {
                                        sadcigs.push(sadcigar);
                                    }
                                }
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
            }

            ctr_dex_1_0::PATHED_MATERIAL_GROUP | ctr_dex_1_0::BIG_PATHED_MATERIAL_GROUP => {
                // Compute size of pathed material based on txt or bny
                let pags = if cold == COLDS.txt {
                    ctr.count() * 4
                } else {
                    ctr.count() * 3
                };

                // Make sure we have enough data
                if self.buffer.len() < pags as usize {
                    return Err(MatterError::NeedMoreDataError(
                        "Needs more data".to_string(),
                    ));
                }

                // Extract the pathed material
                let pims: Vec<u8> = self.buffer.drain(0..pags as usize).collect();
                pathed.push(pims);
            }

            ctr_dex_1_0::ESSR_PAYLOAD_GROUP => {
                for _ in 0..ctr.count() {
                    match self._extractor::<Texter>(cold, pipelined, &VRSN_1_0) {
                        Ok(texter) => essrs.push(texter),
                        Err(e) => return Err(e),
                    }
                }
            }

            _ => {
                return Err(MatterError::UnexpectedCountCodeError(format!(
                    "Unsupported count code={}.",
                    ctr.code()
                )));
            }
        }

        Ok(())
    }

    async fn dispatch_message(&mut self, msg: Message) -> Result<(), KERIError> {
        // Match message type to handler
        match msg {
            Message::KeyEvent {
                serder,
                sigers,
                wigers,
                delseqner,
                delsaider,
                firner,
                dater,
                cigars,
                trqs,
                local,
            } => {
                let sigs = sigers.unwrap_or_default();
                self.handlers.kevery.lock().unwrap().process_event(*serder.clone(), sigs, wigers, delseqner, delsaider, firner.clone(), dater, Some(false), local)?;

                if cigars.is_some() {
                    self.handlers.kevery.lock().unwrap().process_attached_receipt_couples(*serder.clone(), firner.clone(), cigars.unwrap())?;
                }

                if trqs.is_some() {
                    self.handlers.kevery.lock().unwrap().process_attached_receipt_quadruples(*serder, trqs.unwrap(), firner, local)?;
                }
            }
            Message::Receipt {
                serder,
                cigars,
                local,
            } => {
                self.handlers.kevery.lock().unwrap().process_receipt(*serder, cigars, local)?;
            },
            Message::WitnessReceipt {
                serder,
                wigers,
                local,
            } => {
                self.handlers.kevery.lock().unwrap().process_receipt_witness(*serder, wigers, local)?;
            },
            Message::ReceiptTrans {
                serder: _,
                tsgs: _,
                local: _,
            } => {

            },
            Message::Query {
                serder,
                source,
                sigers,
                cigar,
            } => {
                let ked = serder.ked();
                let route = ked["r"].as_str();
                match route {
                    Some(route) => match route {
                        "logs" | "ksn" | "mbx" => {
                            self.handlers.kevery.lock().unwrap().process_query(*serder, source, sigers, cigar)?;
                        },
                        "tels" | "tsn" => {} //self.handlers.tevery.handle(msg).await?,
                        &_ => {}
                    },
                    None => {}
                }
            }
            Message::ReplyNonTrans {
                serder: _,
                cigars: _,
            } => self.handlers.revery.handle(msg).await?,
            Message::ReplyTrans { serder: _, tsgs: _ } => self.handlers.revery.handle(msg).await?,
            Message::ExchangeEventNonTrans {
                serder: _,
                cigars: _,
                pathed: _,
                essrs: _,
            } => self.handlers.exchanger.handle(msg).await?,
            Message::ExchangeEventTrans {
                serder: _,
                tsgs: _,
                pathed: _,
                essrs: _,
            } => self.handlers.exchanger.handle(msg).await?,
            Message::TELEvent {
                serder: _,
                seqner: _,
                saider: _,
                wigers: _,
            } => self.handlers.tevery.handle(msg).await?,
            Message::Credential {
                creder: _,
                prefixer: _,
                seqner: _,
                saider: _,
            } => self.handlers.verifier.handle(msg).await?,
        }
        Ok(())
    }

    // This would typically go inside the impl block for Parser
    fn process_message(
        &self,
        serder: Box<dyn Serder>,
        sigers: Vec<Siger>,
        wigers: Vec<Siger>,
        cigars: Vec<Cigar>,
        trqs: Vec<Trqs>,
        tsgs: Vec<Tsgs>,
        ssgs: Vec<Ssgs>,
        sscs: Vec<Sscs>,
        frcs: Vec<Frcs>,
        ssts: Vec<Ssts>,
        pathed: Vec<Vec<u8>>,
        _sadtsgs: Vec<SadTsgs>,
        _sadcigars: Vec<SadCigars>,
        essrs: Vec<Texter>,
        local: bool,
    ) -> Result<Message, MatterError> {
        // Check if serder is SerderKERI
        if let Some(keri_serder) = serder.as_any().downcast_ref::<SerderKERI>() {
            let ilk = keri_serder.ilk();

            // Check for event messages
            if ilk == Some(Ilk::Icp)
                || ilk == Some(Ilk::Rot)
                || ilk == Some(Ilk::Ixn)
                || ilk == Some(Ilk::Dip)
                || ilk == Some(Ilk::Drt)
            {
                // Extract firner and dater from the last element of frcs
                let (firner, dater) = frcs
                    .last()
                    .map(|frcs| (Some(frcs.seqner.clone()), Some(frcs.dater.clone())))
                    .unwrap_or((None, None));

                // Extract delseqner and delsaider from the last element of sscs
                let (delseqner, delsaider) = sscs
                    .last()
                    .map(|sscs| (Some(sscs.seqner.clone()), Some(sscs.saider.clone())))
                    .unwrap_or((None, None));

                // Validate signatures
                if sigers.is_empty() {
                    let sad = keri_serder.sad();
                    let d = sad["d"].as_str().unwrap();
                    let msg = format!("Missing attached signature(s) for evt = {}", d);
                    tracing::info!("{}", msg);
                    tracing::debug!("Event Body = \n{}\n", keri_serder.pretty(None));
                    return Err(MatterError::ValidationError(msg));
                }

                // Create KeyEvent message
                let message = Message::KeyEvent {
                    serder: Box::new(keri_serder.clone()),
                    sigers: Some(sigers),
                    wigers: if wigers.is_empty() {
                        None
                    } else {
                        Some(wigers)
                    },
                    delseqner,
                    delsaider,
                    firner,
                    dater,
                    cigars: Some(cigars),
                    trqs: Some(trqs),
                    local: Some(local),
                };

                return Ok(message);
            }
            // Receipt message
            else if ilk == Some(Ilk::Rct) {
                if cigars.is_empty() && wigers.is_empty() && tsgs.is_empty() {
                    let msg = format!(
                        "Missing attached signatures on receipt msg sn={} SAID={}",
                        keri_serder.sn().unwrap(),
                        keri_serder.said().unwrap()
                    );
                    tracing::info!("{}", msg);
                    tracing::debug!("Receipt body=\n{}\n", keri_serder.pretty(None));
                    return Err(MatterError::ValidationError(msg));
                }

                if !cigars.is_empty() {
                    return Ok(Message::Receipt {
                        serder: Box::new(keri_serder.clone()),
                        cigars,
                        local: Some(local),
                    });
                }

                if !wigers.is_empty() {
                    return Ok(Message::WitnessReceipt {
                        serder: Box::new(keri_serder.clone()),
                        wigers,
                        local: Some(local),
                    });
                }

                if !tsgs.is_empty() {
                    return Ok(Message::ReceiptTrans {
                        serder,
                        tsgs,
                        local: Some(local),
                    });
                }
            }
            // Reply message
            else if ilk == Some(Ilk::Rpy) {
                if cigars.is_empty() && tsgs.is_empty() {
                    let msg = format!(
                        "Missing attached endorser signature(s) to reply msg = {}",
                        keri_serder.pretty(None)
                    );
                    return Err(MatterError::ValidationError(msg));
                }

                if !cigars.is_empty() {
                    return Ok(Message::ReplyNonTrans { serder, cigars });
                }

                if !tsgs.is_empty() {
                    return Ok(Message::ReplyTrans { serder, tsgs });
                }
            }
            // Query message
            else if ilk == Some(Ilk::Qry) {
                // Check for source and signatures
                return if !sscs.is_empty() {
                    let ssgs = ssgs.last().unwrap();

                    Ok(Message::Query {
                        serder: Box::new(keri_serder.clone()),
                        source: Some(ssgs.prefixer.clone()),
                        sigers: Some(ssgs.sigers.clone()),
                        cigar: None,
                    })
                } else if !cigars.is_empty() {
                    Ok(Message::Query {
                        serder: Box::new(keri_serder.clone()),
                        source: None,
                        sigers: None,
                        cigar: Some(cigars),
                    })
                } else {
                    let msg = format!(
                        "Missing attached requester signature(s) to key log query msg = {}",
                        keri_serder.pretty(None)
                    );
                    Err(MatterError::ValidationError(msg))
                };
            }
            // Exchange message
            else if ilk == Some(Ilk::Exn) {
                if !cigars.is_empty() {
                    return Ok(Message::ExchangeEventNonTrans {
                        serder,
                        cigars,
                        pathed: if pathed.is_empty() {
                            None
                        } else {
                            Some(pathed)
                        },
                        essrs: if essrs.is_empty() { None } else { Some(essrs) },
                    });
                }

                if !tsgs.is_empty() {
                    return Ok(Message::ExchangeEventTrans {
                        serder,
                        tsgs,
                        pathed: if pathed.is_empty() {
                            None
                        } else {
                            Some(pathed)
                        },
                        essrs: if essrs.is_empty() { None } else { Some(essrs) },
                    });
                }

                let msg = format!(
                    "Missing attached signatures for exchange message = {}",
                    keri_serder.pretty(None)
                );
                return Err(MatterError::ValidationError(msg));
            }
            // TEL message
            else if ilk == Some(Ilk::Vcp)
                || ilk == Some(Ilk::Vrt)
                || ilk == Some(Ilk::Iss)
                || ilk == Some(Ilk::Rev)
                || ilk == Some(Ilk::Bis)
                || ilk == Some(Ilk::Brv)
            {
                // Extract seqner and saider from sscs
                let (seqner, saider) = sscs
                    .last()
                    .map(|sscs| (Some(sscs.seqner.clone()), Some(sscs.saider.clone())))
                    .unwrap_or((None, None));

                return Ok(Message::TELEvent {
                    serder,
                    seqner,
                    saider,
                    wigers: if wigers.is_empty() {
                        None
                    } else {
                        Some(wigers)
                    },
                });
            } else {
                let msg = format!(
                    "Unexpected message ilk = {} for evt = {}",
                    ilk.unwrap(),
                    keri_serder.pretty(None)
                );
                return Err(MatterError::ValidationError(msg));
            }
        }
        // Check if serder is SerderACDC
        else if let Some(acdc_serder) = serder.as_any().downcast_ref::<SerderACDC>() {
            let ilk = acdc_serder.ilk();

            return if ilk.is_none() {
                // default for ACDC
                // Extract prefixer, seqner, and saider from ssts
                let (prefixer, seqner, saider) = ssts
                    .last()
                    .map(|ssts| {
                        (
                            Some(ssts.prefixer.clone()),
                            Some(ssts.seqner.clone()),
                            Some(ssts.saider.clone()),
                        )
                    })
                    .unwrap_or((None, None, None));

                Ok(Message::Credential {
                    creder: serder,
                    prefixer,
                    seqner,
                    saider,
                })
            } else {
                let msg = format!(
                    "Unexpected message ilk = {:?} for evt = {}",
                    ilk,
                    acdc_serder.pretty(None)
                );
                Err(MatterError::ValidationError(msg))
            };
        } else {
            let msg = format!(
                "Unexpected protocol type = {} for event message = {}",
                serder.proto(),
                serder.pretty(None)
            );
            return Err(MatterError::ValidationError(msg));
        }

        // If we get here, something went wrong in the logic above
        Err(MatterError::ValidationError(
            "Failed to process message".to_string(),
        ))
    }

    /// Returns a Result containing an instance of the provided type T from the input message stream.
    ///
    /// # Parameters
    /// * `ims` - A mutable reference to bytes that can be stripped
    /// * `cold` - Stream state indicator (txt or bny)
    /// * `abort` - True means abort if bad pipelined frame, False means wait for more data
    /// * `gvrsn` - Instance of genera version of CESR code tables
    ///
    /// # Returns
    /// * `Result<T, MatterError>` - Either the successfully parsed instance or an error
    ///
    /// # Errors
    /// * `ColdStartError` - If the stream state is invalid
    /// * `ShortageError` - If not enough bytes in stream and abort is true
    ///
    /// # Type Parameters
    /// * `T` - A type that implements the Parsable trait (equivalent to Serder, Counter, Matter, Indexer)
    ///
    pub fn _extractor<T: Parsable>(
        &mut self,
        cold: &str,
        abort: bool,
        _gvrsn: &Versionage,
    ) -> Result<T, MatterError> {
        // Try parsing until we either succeed or get a shortage error

        let result = match cold {
            "txt" => T::from_qb64b(&mut self.buffer, Some(true)),
            "bny" => T::from_qb2(&mut self.buffer, Some(true)),
            _ => Err(MatterError::ColdStartError(format!(
                "Invalid stream state cold={:?}.",
                cold
            ))),
        };

        return match result {
            Ok(instance) => Ok(instance),
            Err(MatterError::ShortageError(_)) if !abort => {
                // In Python, this would yield control back to caller
                // In Rust, we need to signal that more data is needed
                Err(MatterError::NeedMoreDataError(
                    "Needs more data".to_string(),
                ))
            }
            Err(err) => Err(err),
        };
    }

    /// Extract sad path signature groups
    ///
    /// # Parameters
    /// * `ctr` - Group type counter
    /// * `ims` - Serialized incoming message stream
    /// * `root` - Optional root path of this group
    /// * `cold` - Next character Coldage type indicator
    /// * `pipelined` - Whether to use pipeline processor
    ///
    /// # Returns
    /// * Vector of tuples containing extracted sad path signature groups
    pub fn sad_path_sig_group(
        &mut self,
        ctr: &BaseCounter,
        root: Option<&Pather>,
        cold: &str,
        pipelined: bool,
        gvrsn: &Versionage,
    ) -> Result<Vec<SadPathGroup>, MatterError> {
        // Verify that the counter code is SadPathSigGroups
        if ctr.code() != ctr_dex_1_0::SAD_PATH_SIG_GROUPS {
            return Err(MatterError::UnexpectedCountCodeError(format!(
                "Wrong count code={}. Expected code={}.",
                ctr.code(),
                ctr_dex_1_0::SAD_PATH_SIG_GROUPS
            )));
        }

        // Extract subpath
        let mut subpath = self._extractor::<Pather>(cold, pipelined, gvrsn)?;

        // Apply root if provided
        // TODO: fix this code to match subpath logic in KERIpy
        if let Some(_) = root {
            subpath = subpath.root();
        }

        // Extract subcounter
        let sctr = self._extractor::<BaseCounter>(cold, pipelined, gvrsn)?;

        let mut result = Vec::new();

        // Process based on subcounter code
        match sctr.code() {
            ctr_dex_1_0::TRANS_IDX_SIG_GROUPS => {
                // Extract TransIdxSigGroups
                let trans_groups = self.trans_idx_sig_groups(&sctr, cold, pipelined, gvrsn)?;

                for tsgs in trans_groups {
                    let group = SadPathGroup::TransIdxSig(
                        SadTsgs {
                            path: subpath.clone(),
                            prefixer: tsgs.prefixer,
                            seqner: tsgs.seqner,
                            saider: tsgs.saider,
                            sigers: tsgs.sigers,
                        }
                        .clone(),
                    );
                    result.push(group);
                }
            }

            ctr_dex_1_0::CONTROLLER_IDX_SIGS => {
                // Extract ControllerIdxSigs
                let mut isigers = Vec::with_capacity(sctr.count() as usize);

                for _ in 0..sctr.count() {
                    let isiger = self._extractor::<Siger>(cold, pipelined, gvrsn)?;
                    isigers.push(isiger);
                }

                let group = SadPathGroup::ControllerIdxSig(SadSigers {
                    path: subpath,
                    sigers: isigers,
                });
                result.push(group);
            }

            ctr_dex_1_0::NON_TRANS_RECEIPT_COUPLES => {
                // Extract NonTransReceiptCouples
                let cigars = self.non_trans_receipt_couples(&sctr, cold, pipelined, gvrsn)?;

                for cigar in cigars {
                    let group = SadPathGroup::NonTransReceipt(SadCigars {
                        path: subpath.clone(),
                        cigar,
                    });
                    result.push(group);
                }
            }

            _ => {
                return Err(MatterError::UnexpectedCountCodeError(format!(
                    "Wrong count code={}. Expected one of TransIdxSigGroups, ControllerIdxSigs, or NonTransReceiptCouples.",
                    sctr.code()
                )));
            }
        }

        Ok(result)
    }

    /// Extract attached trans indexed sig groups, each made of:
    /// - triple pre+snu+dig plus indexed sig group
    /// - pre is pre of signer (endorser) of msg
    /// - snu is sn of signer's est evt when signed
    /// - dig is dig of signer's est event when signed
    /// Followed by counter for ControllerIdxSigs with attached
    /// indexed sigs from trans signer (endorser).
    ///
    /// # Parameters
    /// * `ctr` - Group type counter
    /// * `ims` - Serialized incoming message stream
    /// * `cold` - Next character Coldage type indicator
    /// * `pipelined` - Whether to use pipeline processor
    ///
    /// # Returns
    /// * Vector of tuples containing (prefixer, seqner, saider, isigers)
    pub fn trans_idx_sig_groups(
        &mut self,
        ctr: &BaseCounter,
        cold: &str,
        pipelined: bool,
        gvrsn: &Versionage,
    ) -> Result<Vec<Tsgs>, MatterError> {
        let mut groups = Vec::with_capacity(ctr.count() as usize);

        for _ in 0..ctr.count() {
            // Extract prefixer
            let prefixer = self._extractor::<Prefixer>(cold, pipelined, gvrsn)?;

            // Extract seqner
            let seqner = self._extractor::<Seqner>(cold, pipelined, gvrsn)?;

            // Extract saider
            let saider = self._extractor::<Saider>(cold, pipelined, gvrsn)?;

            // Extract counter for ControllerIdxSigs
            let ictr = self._extractor::<BaseCounter>(cold, pipelined, gvrsn)?;

            // Verify that the counter code is ControllerIdxSigs
            if ictr.code() != ctr_dex_1_0::CONTROLLER_IDX_SIGS {
                return Err(MatterError::UnexpectedCountCodeError(format!(
                    "Wrong count code={}. Expected code={}.",
                    ictr.code(),
                    ctr_dex_1_0::CONTROLLER_IDX_SIGS
                )));
            }

            // Extract each attached signature
            let mut isigers = Vec::with_capacity(ictr.count() as usize);
            for _ in 0..ictr.count() {
                let isiger = self._extractor::<Siger>(cold, pipelined, gvrsn)?;
                isigers.push(isiger);
            }

            // Add the group to our results
            groups.push(Tsgs {
                prefixer,
                seqner,
                saider,
                sigers: isigers,
            });
        }

        Ok(groups)
    }

    /// Extract attached receipt couplets into a vector of cigars
    /// Verfer property of each cigar is the identifier prefix
    /// Cigar itself has the attached signature
    ///
    /// # Parameters
    /// * `ctr` - Counter with count field indicating number of attachments
    /// * `ims` - Input stream containing serialized message data
    /// * `cold` - Character coldage type indicator
    /// * `pipelined` - Whether to use pipeline processor for stream
    ///
    /// # Returns
    /// * Vector of Cigar objects with attached verfers
    pub fn non_trans_receipt_couples(
        &mut self,
        ctr: &BaseCounter,
        cold: &str,
        pipelined: bool,
        gvrsn: &Versionage,
    ) -> Result<Vec<Cigar>, MatterError> {
        let mut cigars = Vec::with_capacity(ctr.count() as usize);

        for _ in 0..ctr.count() {
            // Extract verfer
            let verfer = self._extractor::<Verfer>(cold, pipelined, gvrsn)?;

            // Extract cigar
            let mut cigar = self._extractor::<Cigar>(cold, pipelined, gvrsn)?;

            // Attach verfer to cigar
            cigar.verfer = Some(verfer);

            // Add to results
            cigars.push(cigar);
        }

        Ok(cigars)
    }
}

#[cfg(test)]
mod tests {
    use crate::cesr::BaseMatter;
    use crate::cesr::signing::{Salter, Sigmat};
    use crate::keri::core::eventing::{InceptionEventBuilder, InteractEventBuilder, Kever, KeveryBuilder, RotateEventBuilder};
    use crate::keri::core::serdering::Rawifiable;
    use crate::keri::db::basing::Baser;
    use crate::keri::db::dbing::LMDBer;
    use crate::Matter;
    use super::*;

    struct MockHandler {
        serder: Option<Box<dyn Serder>>,
    }

    #[async_trait::async_trait]
    impl MessageHandler for MockHandler {
        async fn handle(&self, _msg: Message) -> Result<(), KERIError> {
            let serder = match _msg {
                Message::KeyEvent { serder, .. } => Some(Box::new(serder)),
                _ => None,
            };
            if serder.is_some() {
                println!("{}", serder.unwrap().pretty(None));
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_parser_valid_message() {
        // Provide CESR-encoded message bytes matching KERIpy tests
        let pre = "DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx";
        let said = "EIcca2-uqsicYK7-q5gxlZXuzOkqrNSL3JIaLflSOOgF";
        
        let input = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXuzOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}-AABAAApXLez5eVIs6YyRXOMDMBy4cTm2GvsilrZlcMmtBbO5twLst_jjFoEyfKTWKntEtv9JPBv1DLkqg-ImDmGPM8E"#.as_bytes();
        let reader = tokio::io::BufReader::new(input);

        // Create a temporary database
        let lmdber = &LMDBer::builder()
            .temp(true)
            .name("test_kevery_builder")
            .build().expect("LMDBer should be build");

        let db =
            Baser::new(Arc::new(lmdber)).expect("Baser should be built");

        // Create Kevery using the builder pattern
        let kevery = KeveryBuilder::new(Arc::new(&db))
            .with_lax(true)
            .with_local(false)
            .with_cloned(false)
            .with_direct(true)
            .with_check(false)
            .build().expect("Should build a Kevery");


        let handlers = Handlers {
            kevery: Arc::new(kevery.into()),
            tevery: Arc::new(MockHandler { serder: None }),
            exchanger: Arc::new(MockHandler { serder: None }),
            revery: Arc::new(MockHandler { serder: None }),
            verifier: Arc::new(MockHandler { serder: None }),
            local: false,
        };

        let mut parser = Parser::new(reader, true, false, handlers);
        assert!(parser.parse_stream(Some(true)).await.is_ok());

        let msgs = db.clone_pre_iter("DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx", None).expect("Clone failed");
        assert_eq!(msgs.len(), 1);
        let msg = msgs.get(0).unwrap();

        let bytes = concat!(
        r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXuzOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}"#,
        r#"-VAn-AABAAApXLez5eVIs6YyRXOMDMBy4cTm2GvsilrZlcMmtBbO5twLst_jjFoEyfKTWKntEtv9JPBv1DLkqg-ImDmGPM8E"#
        ).as_bytes();

        assert!(msg.starts_with(bytes));
    }

    #[tokio::test]
    async fn test_parser() -> Result<(), KERIError> {
        // Create signers
        let raw = b"ABCDEFGH01234567";
        let salter = Salter::new(Some(raw), None, None);
        let signers = salter.unwrap().signers(8, 0, "psr", None, None, None, true)?;

        // Create databases
        let con_lmdber = LMDBer::builder().name("controller").temp(true).build()?;
        let val_lmdber = LMDBer::builder().name("validator").temp(true).build()?;

        let con_db = Baser::new(Arc::new(&con_lmdber))?;
        let val_db = Baser::new(Arc::new(&val_lmdber))?;

        let mut event_digs = Vec::new();
        let mut msgs = Vec::new();

        let keys = vec![signers[0].verfer.qb64()];
        let ndigs = vec![BaseMatter::from_qb64(&signers[1].verfer.qb64())?.qb64()];

        let serder = InceptionEventBuilder::new(keys)
            .with_ndigs(ndigs)
            .build()?;

        event_digs.push(serder.said().unwrap());

        // Create sig counter
        let counter = BaseCounter::from_code_and_count(Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS), Some(1), Some("1.0")).unwrap();

        // Sign serialization
        let siger = match signers[0].sign(&serder.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            Sigmat::NonIndexed(_) => {panic!("Should not be non-indexed")}
        };

        // Create key event verifier state
        let mut kever = Kever::new(
            Arc::new(&con_db),
            None,
            Some(serder.clone()),
            Some(vec![siger.clone()]),
            None, None, None, None, None, None, None, None, None
        )?;

        // Extend key event stream
        msgs.extend_from_slice(&serder.raw());
        msgs.extend_from_slice(&counter.qb64b());
        msgs.extend_from_slice(&siger.qb64b());

        // Event 1: Rotation Transferable
        let pre = kever.prefixer().unwrap().qb64();
        let keys = vec![signers[1].verfer.qb64()];
        let dig = kever.serder().unwrap().said().unwrap();
        let ndigs = vec![BaseMatter::from_qb64(&signers[2].verfer.qb64()).unwrap().qb64()];

        let serder = RotateEventBuilder::new(pre, keys, dig.to_string())
            .with_sn(1)
            .with_ndigs(ndigs)
            .build()?;

        event_digs.push(serder.said().unwrap());

        // Create sig counter
        let counter = BaseCounter::from_code_and_count(Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS), Some(1), Some("1.0"))?;

        // Sign serialization
        let siger = match signers[1].sign(&serder.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            Sigmat::NonIndexed(_) => {panic!("Should not be non-indexed")}
        };

        // Update key event verifier state
        kever.update(
            serder.clone(),
            vec![siger.clone()],
            None, None, None, None, None,
            true,
            true,
            false
        )?;

        // Extend key event stream
        msgs.extend_from_slice(&serder.raw());
        msgs.extend_from_slice(&counter.qb64b());
        msgs.extend_from_slice(&siger.qb64b());

        // Event 2: Rotation Transferable
        let pre = kever.prefixer().unwrap().qb64();
        let keys = vec![signers[2].verfer.qb64()];
        let dig = kever.serder().unwrap().said().unwrap();
        let ndigs = vec![BaseMatter::from_qb64(&signers[3].verfer.qb64()).unwrap().qb64()];

        let serder = RotateEventBuilder::new(pre, keys, dig.to_string())
            .with_sn(2)
            .with_ndigs(ndigs)
            .build()?;

        event_digs.push(serder.said().unwrap());

        // Create sig counter
        let counter = BaseCounter::from_code_and_count(Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS), Some(1), Some("1.0")).unwrap();

        // Sign serialization
        let siger = match signers[2].sign(&serder.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            Sigmat::NonIndexed(_) => {panic!("Should not be non-indexed")}
        };

        // Update key event verifier state
        kever.update(
            serder.clone(),
            vec![siger.clone()],
            None, None, None, None, None,
            true,
            true,
            false
        )?;

        // Extend key event stream
        msgs.extend_from_slice(&serder.raw());
        msgs.extend_from_slice(&counter.qb64b());
        msgs.extend_from_slice(&siger.qb64b());

        // Event 3: Interaction
        let pre = kever.prefixer().unwrap().qb64();
        let dig = kever.serder().unwrap().said().unwrap();

        let serder = InteractEventBuilder::new(pre, dig.to_string()).with_sn(3)
            .build()?;

        event_digs.push(serder.said().unwrap());

        // Create sig counter
        let counter = BaseCounter::from_code_and_count(Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS), Some(1), Some("1.0")).unwrap();

        // Sign serialization
        let siger = match signers[2].sign(&serder.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            Sigmat::NonIndexed(_) => {panic!("Should not be non-indexed")}
        };

        // Update key event verifier state
        kever.update(
            serder.clone(),
            vec![siger.clone()],
            None, None, None, None, None,
            true,
            true,
            false
        )?;

        // Extend key event stream
        msgs.extend_from_slice(&serder.raw());
        msgs.extend_from_slice(&counter.qb64b());
        msgs.extend_from_slice(&siger.qb64b());

        // Event 4: Interaction
        let pre = kever.prefixer().unwrap().qb64();
        let dig = kever.serder().unwrap().said().unwrap();

        let serder = InteractEventBuilder::new(pre, dig.to_string())
            .with_sn(4)
            .build()?;

        event_digs.push(serder.said().unwrap());

        // Create sig counter
        let counter = BaseCounter::from_code_and_count(Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS), Some(1), Some("1.0"))?;

        // Sign serialization
        let siger = match signers[2].sign(&serder.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            Sigmat::NonIndexed(_) => {panic!("Should not be non-indexed")}
        };

        // Update key event verifier state
        kever.update(
            serder.clone(),
            vec![siger.clone()],
            None, None, None, None, None,
            true,
            true,
            false
        )?;

        // Extend key event stream
        msgs.extend_from_slice(&serder.raw());
        msgs.extend_from_slice(&counter.qb64b());
        msgs.extend_from_slice(&siger.qb64b());

        // Event 5: Rotation Transferable
        let pre = kever.prefixer().unwrap().qb64();
        let keys = vec![signers[3].verfer.qb64()];
        let dig = kever.serder().unwrap().said().unwrap();
        let ndigs = vec![BaseMatter::from_qb64(&signers[4].verfer.qb64())?.qb64()];

        let serder = RotateEventBuilder::new(pre, keys, dig.to_string())
            .with_sn(5)
            .with_ndigs(ndigs)
            .build()?;
        event_digs.push(serder.said().unwrap());

        // Create sig counter
        let counter = BaseCounter::from_code_and_count(Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS), Some(1), Some("1.0")).unwrap();

        // Sign serialization
        let siger = match signers[3].sign(&serder.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            Sigmat::NonIndexed(_) => {panic!("Should not be non-indexed")}
        };

        // Update key event verifier state
        kever.update(
            serder.clone(),
            vec![siger.clone()],
            None, None, None, None, None,
            true,
            true,
            false
        )?;

        // Extend key event stream
        msgs.extend_from_slice(&serder.raw());
        msgs.extend_from_slice(&counter.qb64b());
        msgs.extend_from_slice(&siger.qb64b());

        // Event 6: Interaction
        let pre = kever.prefixer().unwrap().qb64();
        let dig = kever.serder().unwrap().said().unwrap();

        let serder = InteractEventBuilder::new(pre, dig.to_string())
            .with_sn(6)
            .build()?;
        event_digs.push(serder.said().unwrap());

        // Create sig counter
        let counter = BaseCounter::from_code_and_count(Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS), Some(1), Some("1.0"))?;

        // Sign serialization
        let siger = match signers[3].sign(&serder.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            Sigmat::NonIndexed(_) => {panic!("Should not be non-indexed")}
        };

        // Update key event verifier state
        kever.update(
            serder.clone(),
            vec![siger.clone()],
            None, None, None, None, None,
            true,
            true,
            false
        )?;

        // Extend key event stream
        msgs.extend_from_slice(&serder.raw());
        msgs.extend_from_slice(&counter.qb64b());
        msgs.extend_from_slice(&siger.qb64b());

        // Event 7: Rotation to null NonTransferable Abandon
        // nxt digest is empty (no ndigs)
        let pre = kever.prefixer().unwrap().qb64();
        let keys = vec![signers[4].verfer.qb64()];
        let dig = kever.serder().unwrap().said().unwrap();

        let serder = RotateEventBuilder::new(pre, keys, dig.to_string())
            .with_sn(7)
            // ndigs is intentionally empty - this makes the key non-transferable
            .with_ndigs(vec![])
            .build()?;

        event_digs.push(serder.said().unwrap());

        // Create sig counter
        let counter = BaseCounter::from_code_and_count(Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS), Some(1), Some("1.0"))?;

        // Sign serialization
        let siger = match signers[4].sign(&serder.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            Sigmat::NonIndexed(_) => {panic!("Should not be non-indexed")}
        };

        // Update key event verifier state
        kever.update(
            serder.clone(),
            vec![siger.clone()],
            None, None, None, None, None,
            true,
            true,
            false
        )?;

        // Extend key event stream
        msgs.extend_from_slice(&serder.raw());
        msgs.extend_from_slice(&counter.qb64b());
        msgs.extend_from_slice(&siger.qb64b());

        // Event 8: Interaction but already abandoned
        let pre = kever.prefixer().unwrap().qb64();
        let dig = kever.serder().unwrap().said().unwrap();

        let serder = InteractEventBuilder::new(pre, dig.to_string())
            .with_sn(8)
            .build()?;

        // Create sig counter
        let counter = BaseCounter::from_code_and_count(Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS), Some(1), Some("1.0")).unwrap();

        // Sign serialization
        let siger = match signers[4].sign(&serder.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            Sigmat::NonIndexed(_) => {panic!("Should not be non-indexed")}
        };

        // Update key event verifier state - should fail because abandoned
        let result = kever.update(
            serder.clone(),
            vec![siger.clone()],
            None, None, None, None, None,
            true,
            true,
            false
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KERIError::ValidationError(_)));

        // Extend key event stream anyway
        msgs.extend_from_slice(&serder.raw());
        msgs.extend_from_slice(&counter.qb64b());
        msgs.extend_from_slice(&siger.qb64b());

        // Event 8: Rotation override interaction but already abandoned
        let pre = kever.prefixer().unwrap().qb64();
        let keys = vec![signers[4].verfer.qb64()];
        let dig = kever.serder().unwrap().said().unwrap();
        let ndigs = vec![BaseMatter::from_qb64(&signers[5].verfer.qb64()).unwrap().qb64()];

        let serder = RotateEventBuilder::new(pre, keys, dig.to_string())
            .with_sn(8)
            .with_ndigs(ndigs)
            .build()?;

        // Create sig counter
        let counter = BaseCounter::from_code_and_count(Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS), Some(1), Some("1.0")).unwrap();

        // Sign serialization
        let siger = match signers[4].sign(&serder.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            Sigmat::NonIndexed(_) => {panic!("Should not be non-indexed")}
        };

        // Update key event verifier state - should fail because nontransferable
        let result = kever.update(
            serder.clone(),
            vec![siger.clone()],
            None, None, None, None, None,
            true,
            true,
            false
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KERIError::ValidationError(_)));

        // Extend key event stream anyway
        msgs.extend_from_slice(&serder.raw());
        msgs.extend_from_slice(&counter.qb64b());
        msgs.extend_from_slice(&siger.qb64b());

        // Assert message length
        assert_eq!(msgs.len(), 3745);

        let pre = kever.prefixer().unwrap().qb64();

        // Check db digs
        let db_digs: Vec<String> = con_db.clone_pre_iter(&pre, None)?
            .iter()
            .map(|msg| {
                let serder = SerderKERI::from_raw(&msg, None).unwrap();
                serder.said().unwrap().to_string()
            })
            .collect();

        assert_eq!(db_digs, event_digs);

        // Create Kevery and Parser
        let kevery = Kevery::new(
            None,
            Arc::new(&val_db),
            None,
            Some(false),
            Some(false),
            Some(false),
            Some(false),
            Some(false)
        )?;

        let handlers = Handlers {
            kevery: Arc::new(Mutex::new(kevery)),
            tevery: Arc::new(MockHandler { serder: None }),
            exchanger: Arc::new(MockHandler { serder: None }),
            revery: Arc::new(MockHandler { serder: None }),
            verifier: Arc::new(MockHandler { serder: None }),
            local: false,
        };

        let mut parser = Parser::new(msgs.as_slice(), true, false, handlers);

        // Parse the messages
        assert!(parser.parse_stream(Some(true)).await.is_ok());

        // Check parsed results
        assert!(parser.handlers.kevery.lock().unwrap().kevers().contains_key(&pre));

        let vkever = parser.handlers.kevery.lock().unwrap().kevers().get(&pre).unwrap();
        // let vkever = (parser.handlers.kevery.lock().await).kevers()[&pre].clone();
        assert_eq!(vkever.sner().unwrap().num(), kever.sner().unwrap().num());
        assert_eq!(vkever.verfers().unwrap()[0].qb64(), kever.verfers().unwrap()[0].qb64());
        assert_eq!(vkever.verfers().unwrap()[0].qb64(), signers[4].verfer.qb64());

        // Check val_db digs
        let val_db_digs: Vec<String> = val_db.clone_pre_iter(&pre, None)?
            .iter()
            .map(|msg| {
                let serder = SerderKERI::from_raw(&msg, None).unwrap();
                serder.said().unwrap().to_string()
            })
            .collect();

        assert_eq!(val_db_digs, event_digs);

        // Test parser without kevery
        // Mock a parser with no handlers
        let mut no_handler_parser = Parser::new(msgs.as_slice(), true, false, Handlers::default());
        assert!(no_handler_parser.parse_stream(Some(true)).await.is_ok());

        // Cleanup should be automatic because we're using temp databases
        Ok(())
    }

    impl Default for Handlers<'_> {
        fn default() -> Self {
            // Create minimal handlers for testing
            let lmdber = LMDBer::builder().temp(true).name("temp").build().unwrap();
            let db = Arc::new(&Baser::new(Arc::new(&lmdber)).unwrap());

            let kevery = Kevery::new(
                None, db, None, Some(false), Some(false),
                Some(false), Some(false), Some(false)
            ).unwrap();

            Handlers {
                kevery: Arc::new(Mutex::new(kevery)),
                tevery: Arc::new(MockHandler { serder: None }),
                exchanger: Arc::new(MockHandler { serder: None }),
                revery: Arc::new(MockHandler { serder: None }),
                verifier: Arc::new(MockHandler { serder: None }),
                local: false,
            }
        }
    }
    
    
}
