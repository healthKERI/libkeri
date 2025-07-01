// use crate::cesr::dater::Dater;
// use crate::cesr::indexing::siger::Siger;
// use crate::cesr::Matter::tables::Codex;
// use crate::cesr::prefixer::Prefixer;
// use crate::cesr::saider::Saider;
// use crate::cesr::seqner::Seqner;
// use crate::cesr::verfer::Verfer;
// use crate::cesr::diger::Diger;
// use crate::cesr::tholder::Tholder;
// use crate::keri::core::eventing::kevery::Kevery;
// use crate::keri::app::keeping::Manager;
// use crate::keri::core::parsing::Parser;
// use crate::keri::core::routing::Router;
// use crate::keri::core::serdering::{Rawifiable, Serder};
// use crate::keri::db::basing::Baser;
// use crate::keri::db::dbing::keys::{dg_key, sn_key};
// use crate::keri::db::subing::Suber;
// use crate::keri::{Ilk, KERIError, Roles, Schemes};
// use crate::Matter;
// use std::collections::HashMap;
// use std::sync::Arc;
// use tracing::{debug, info};
// 
// /// Base Habitat (Hab) for managing KERI identifiers and their key state
// pub struct BaseHab<'db> {
//     /// Key store instance
//     pub ks: Arc<dyn Suber>,
// 
//     /// Database instance
//     pub db: Arc<&'db Baser<'db>>,
// 
//     /// Configuration
//     pub cf: HashMap<String, serde_json::Value>,
// 
//     /// Manager for cryptographic operations
//     pub mgr: Arc<Manager<'db>>,
// 
//     /// Router for message routing
//     pub rtr: Arc<Router<'db>>,
// 
//     /// Recovery module
//     pub rvy: Option<Arc<dyn Suber>>,
// 
//     /// Key event verifier
//     pub kvy: Arc<Kevery<'db>>,
// 
//     /// Parser for KERI messages
//     pub psr: Arc<Parser<'db>>,
// 
//     /// Habitat name
//     pub name: String,
// 
//     /// Namespace
//     pub ns: Option<String>,
// 
//     /// Prefix identifier
//     pub pre: Option<String>,
// 
//     /// Temporary flag
//     pub temp: bool,
// 
//     /// Initialization flag
//     pub inited: bool,
// 
//     /// Delegator prefix if delegated
//     pub delpre: Option<String>,
// }
// 
// impl<'db> BaseHab<'db> {
//     /// Create a new BaseHab instance
//     #[allow(clippy::too_many_arguments)]
//     pub fn new(
//         ks: Arc<dyn Suber>,
//         db: Arc<&'db Baser<'db>>,
//         cf: HashMap<String, serde_json::Value>,
//         mgr: Arc<Manager<'db>>,
//         rtr: Arc<Router<'db>>,
//         rvy: Option<Arc<dyn Suber>>,
//         kvy: Arc<Kevery<'db>>,
//         psr: Arc<Parser<'db>>,
//         name: Option<String>,
//         ns: Option<String>,
//         pre: Option<String>,
//         temp: Option<bool>,
//     ) -> Self {
//         Self {
//             ks,
//             db,
//             cf,
//             mgr,
//             rtr,
//             rvy,
//             kvy,
//             psr,
//             name: name.unwrap_or_else(|| "test".to_string()),
//             ns,
//             pre,
//             temp: temp.unwrap_or(false),
//             inited: false,
//             delpre: None,
//         }
//     }
// 
//     /// Make an inception or delegation event
//     #[allow(clippy::too_many_arguments)]
//     pub fn make(
//         &mut self,
//         dnd: bool,
//         code: Option<String>,
//         data: Option<Vec<HashMap<String, serde_json::Value>>>,
//         delpre: Option<String>,
//         est_only: bool,
//         isith: Option<String>,
//         verfers: Vec<Verfer>,
//         nsith: Option<String>,
//         digers: Option<Vec<Diger>>,
//         toad: Option<u32>,
//         wits: Vec<String>,
//     ) -> Result<SerderKERI, KERIError> {
//         let icount = verfers.len();
//         let ncount = digers.as_ref().map(|d| d.len()).unwrap_or(0);
// 
//         let isith = isith.unwrap_or_else(|| {
//             format!("{:x}", std::cmp::max(1, (icount + 1) / 2))
//         });
// 
//         let nsith = nsith.unwrap_or_else(|| {
//             format!("{:x}", std::cmp::max(0, (ncount + 1) / 2))
//         });
// 
//         let cst = Tholder::new(Some(isith.clone()), None, None, None)?.sith();
//         let nst = Tholder::new(Some(nsith.clone()), None, None, None)?.sith();
// 
//         let mut cnfg = Vec::new();
//         if est_only {
//             cnfg.push(TraitDex::EstOnly);
//         }
//         if dnd {
//             cnfg.push(TraitDex::DoNotDelegate);
//         }
// 
//         self.delpre = delpre.clone();
//         let keys: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();
// 
//         let serder = if let Some(dp) = delpre {
//             eventing::delcept(
//                 keys,
//                 dp,
//                 cst,
//                 nst,
//                 digers.unwrap_or_default().iter().map(|d| d.qb64()).collect(),
//                 toad.unwrap_or(0),
//                 wits,
//                 cnfg,
//                 code,
//             )?
//         } else {
//             eventing::incept(
//                 keys,
//                 cst,
//                 nst,
//                 digers.unwrap_or_default().iter().map(|d| d.qb64()).collect(),
//                 toad.unwrap_or(0),
//                 wits,
//                 cnfg,
//                 code,
//                 data.unwrap_or_default(),
//             )?
//         };
// 
//         Ok(serder)
//     }
// 
//     /// Save habitat to database
//     pub fn save(&self, habord: HashMap<String, serde_json::Value>) -> Result<(), KERIError> {
//         if let Some(pre) = &self.pre {
//             self.db.habs.pin(&[pre], &serde_json::to_vec(&habord)?)?;
// 
//             let ns = self.ns.as_deref().unwrap_or("");
//             let name_key = format!("{}:{}", ns, self.name);
// 
//             if self.db.names.get::<_, Vec<u8>>(&[&name_key])?.is_some() {
//                 return Err(KERIError::ValueError("AID already exists with that name".to_string()));
//             }
// 
//             self.db.names.pin(&[&name_key], pre.as_bytes())?;
//         }
//         Ok(())
//     }
// 
//     /// Reconfigure habitat from configuration
//     pub fn reconfigure(&self) -> Result<(), KERIError> {
//         if let Some(pre) = &self.pre {
//             if let Some(conf) = self.cf.get(&self.name) {
//                 if let Some(dt_str) = conf.get("dt").and_then(|v| v.as_str()) {
//                     let dt = Dater::from_iso8601(dt_str)?;
//                     let mut msgs = Vec::new();
// 
//                     msgs.extend(self.make_end_role(
//                         pre.clone(),
//                         Roles::Controller,
//                         Some(dt.to_iso8601()),
//                     )?);
// 
//                     if let Some(curls) = conf.get("curls").and_then(|v| v.as_array()) {
//                         for url_val in curls {
//                             if let Some(url) = url_val.as_str() {
//                                 let parsed_url = url::Url::parse(url)
//                                     .map_err(|e| KERIError::ValueError(format!("Invalid URL: {}", e)))?;
//                                 let scheme = match parsed_url.scheme() {
//                                     "http" => Schemes::Http,
//                                     "https" => Schemes::Https,
//                                     _ => Schemes::Http,
//                                 };
// 
//                                 msgs.extend(self.make_loc_scheme(
//                                     url.to_string(),
//                                     Some(pre.clone()),
//                                     scheme,
//                                     Some(dt.to_iso8601()),
//                                 )?);
//                             }
//                         }
//                     }
// 
//                     self.psr.parse(&msgs)?;
//                 }
//             }
//         }
//         Ok(())
//     }
// 
//     /// Get inception event serder
//     pub fn iserder(&self) -> Result<SerderKERI, KERIError> {
//         if let Some(pre) = &self.pre {
//             let sn_key = sn_key(pre, 0);
//             let dig = self.db.kels.get_last::<_, Vec<u8>>(&[&sn_key])?
//                 .ok_or_else(|| KERIError::ConfigurationError(
//                     format!("Missing inception event in KEL for Habitat pre={}", pre)
//                 ))?;
// 
//             let dig_str = String::from_utf8(dig)
//                 .map_err(|_| KERIError::ValueError("Invalid UTF-8 in digest".to_string()))?;
// 
//             let dg_key = dg_key(pre, &dig_str);
//             let raw = self.db.evts.get::<_, Vec<u8>>(&[&dg_key])?
//                 .ok_or_else(|| KERIError::ConfigurationError(
//                     format!("Missing inception event for Habitat pre={}", pre)
//                 ))?;
// 
//             return SerderKERI::from_raw(&raw, None);
//         }
// 
//         Err(KERIError::ValueError("No prefix set for habitat".to_string()))
//     }
// 
//     /// Get reference to kevers
//     pub fn kevers(&self) -> &std::collections::HashMap<String, crate::keri::core::eventing::kever::Kever<'db>> {
//         self.kvy.kevers()
//     }
// 
//     /// Check if habitat is accepted (has kever)
//     pub fn accepted(&self) -> bool {
//         if let Some(pre) = &self.pre {
//             self.kevers().contains_key(pre)
//         } else {
//             false
//         }
//     }
// 
//     /// Get kever for this habitat
//     pub fn kever(&self) -> Option<&crate::keri::core::eventing::kever::Kever<'db>> {
//         if let Some(pre) = &self.pre {
//             if self.accepted() {
//                 return self.kevers().get(pre);
//             }
//         }
//         None
//     }
// 
//     /// Get prefixes
//     pub fn prefixes(&self) -> &indexmap::IndexSet<String> {
//         self.kvy.prefixes()
//     }
// 
//     /// Create inception event
//     pub fn incept(&mut self, args: HashMap<String, serde_json::Value>) -> Result<SerderKERI, KERIError> {
//         // Extract arguments and call make
//         // This is a simplified version - in practice you'd need to properly parse all arguments
//         todo!("Implement incept method with proper argument parsing")
//     }
// 
//     /// Create rotation event
//     #[allow(clippy::too_many_arguments)]
//     pub fn rotate(
//         &self,
//         verfers: Option<Vec<Verfer>>,
//         digers: Option<Vec<Diger>>,
//         isith: Option<String>,
//         nsith: Option<String>,
//         toad: Option<u32>,
//         cuts: Option<Vec<String>>,
//         adds: Option<Vec<String>>,
//         data: Option<Vec<HashMap<String, serde_json::Value>>>,
//     ) -> Result<Vec<u8>, KERIError> {
//         let kever = self.kever()
//             .ok_or_else(|| KERIError::ValueError("No kever found for habitat".to_string()))?;
// 
//         let verfers = verfers.unwrap_or_else(|| kever.verfers().unwrap_or_default());
//         let digers = digers.unwrap_or_default();
// 
//         let isith = isith.or_else(|| kever.ntholder().map(|h| h.sith().clone()))
//             .unwrap_or_else(|| format!("{:x}", std::cmp::max(1, (verfers.len() + 1) / 2)));
// 
//         let nsith = nsith.unwrap_or_else(|| isith.clone());
// 
//         let cst = Tholder::new(Some(isith), None, None, None)?.sith();
//         let nst = Tholder::new(Some(nsith), None, None, None)?.sith();
// 
//         let keys: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();
// 
//         // Validate rotation against prior next keys
//         let indices: Vec<u32> = kever.ndigers().unwrap_or_default().iter().enumerate()
//             .filter_map(|(idx, diger)| {
//                 let pdigs: Vec<String> = verfers.iter()
//                     .map(|v| Diger::new(Some(v.qb64b()), Some(diger.code())).unwrap().qb64())
//                     .collect();
//                 if pdigs.contains(&diger.qb64()) {
//                     Some(idx as u32)
//                 } else {
//                     None
//                 }
//             })
//             .collect();
// 
//         if let Some(ntholder) = kever.ntholder() {
//             if !ntholder.satisfy(&indices) {
//                 return Err(KERIError::ValidationError(
//                     "Invalid rotation, new key set unable to satisfy prior next signing threshold".to_string()
//                 ));
//             }
//         }
// 
//         let serder = if let Some(delpre) = kever.delpre() {
//             eventing::deltate(
//                 kever.prefixer().unwrap().qb64(),
//                 keys,
//                 kever.serder().unwrap().said().unwrap_or_default(),
//                 kever.sner().unwrap().num() + 1,
//                 cst,
//                 nst,
//                 digers.iter().map(|d| d.qb64()).collect(),
//                 toad.unwrap_or(0),
//                 kever.wits().clone(),
//                 cuts.unwrap_or_default(),
//                 adds.unwrap_or_default(),
//                 data.unwrap_or_default(),
//             )?
//         } else {
//             eventing::rotate(
//                 kever.prefixer().unwrap().qb64(),
//                 keys,
//                 kever.serder().unwrap().said().unwrap_or_default(),
//                 kever.sner().unwrap().num() + 1,
//                 cst,
//                 nst,
//                 digers.iter().map(|d| d.qb64()).collect(),
//                 toad.unwrap_or(0),
//                 kever.wits().clone(),
//                 cuts.unwrap_or_default(),
//                 adds.unwrap_or_default(),
//                 data.unwrap_or_default(),
//             )?
//         };
// 
//         let sigers = self.sign(&serder.raw(), Some(verfers), true, None, None)?;
//         let msg = eventing::messagize(&serder, Some(sigers), None, None, true)?;
// 
//         // Process the event
//         self.kvy.process_event(
//             serder,
//             sigers,
//             None, // wigers
//             None, // delseqner
//             None, // delsaider
//             None, // firner
//             None, // dater
//             None, // eager
//             None, // local
//         ).map_err(|e| KERIError::ValidationError(
//             format!("Improper Habitat rotation for pre={:?}: {}", self.pre, e)
//         ))?;
// 
//         Ok(msg)
//     }
// 
//     /// Create interaction event
//     pub fn interact(
//         &self,
//         data: Option<Vec<HashMap<String, serde_json::Value>>>,
//     ) -> Result<Vec<u8>, KERIError> {
//         let kever = self.kever()
//             .ok_or_else(|| KERIError::ValueError("No kever found for habitat".to_string()))?;
// 
//         let serder = eventing::interact(
//             kever.prefixer().unwrap().qb64(),
//             kever.serder().unwrap().said().unwrap_or_default(),
//             kever.sner().unwrap().num() + 1,
//             data.unwrap_or_default(),
//         )?;
// 
//         let sigers = self.sign(&serder.raw(), None, true, None, None)?;
//         let msg = eventing::messagize(&serder, Some(sigers), None, None, true)?;
// 
//         // Process the event
//         self.kvy.process_event(
//             serder,
//             sigers,
//             None, // wigers
//             None, // delseqner
//             None, // delsaider
//             None, // firner
//             None, // dater
//             None, // eager
//             None, // local
//         ).map_err(|e| KERIError::ValidationError(
//             format!("Improper Habitat interaction for pre={:?}: {}", self.pre, e)
//         ))?;
// 
//         Ok(msg)
//     }
// 
//     /// Sign serialized data
//     pub fn sign(
//         &self,
//         ser: &[u8],
//         verfers: Option<Vec<Verfer>>,
//         indexed: bool,
//         indices: Option<Vec<u32>>,
//         ondices: Option<Vec<u32>>,
//     ) -> Result<Vec<Siger>, KERIError> {
//         let verfers = verfers.or_else(|| {
//             self.kever().and_then(|k| k.verfers())
//         }).ok_or_else(|| KERIError::ValueError("No verfers available for signing".to_string()))?;
// 
//         self.mgr.sign(ser, verfers, indexed, indices, ondices)
//     }
// 
//     /// Decrypt data
//     pub fn decrypt(
//         &self,
//         ser: &str,
//         verfers: Option<Vec<Verfer>>,
//     ) -> Result<Vec<u8>, KERIError> {
//         let verfers = verfers.or_else(|| {
//             self.kever().and_then(|k| k.verfers())
//         }).ok_or_else(|| KERIError::ValueError("No verfers available for decryption".to_string()))?;
// 
//         self.mgr.decrypt(ser, verfers)
//     }
// 
//     /// Create query message
//     pub fn query(
//         &self,
//         pre: String,
//         src: String,
//         query: Option<HashMap<String, serde_json::Value>>,
//     ) -> Result<Vec<u8>, KERIError> {
//         let mut query = query.unwrap_or_default();
//         query.insert("i".to_string(), serde_json::Value::String(pre));
//         query.insert("src".to_string(), serde_json::Value::String(src));
// 
//         let serder = eventing::query(query)?;
//         self.endorse(&serder, true, true)
//     }
// 
//     /// Endorse a message
//     pub fn endorse(
//         &self,
//         serder: &SerderKERI,
//         last: bool,
//         pipelined: bool,
//     ) -> Result<Vec<u8>, KERIError> {
//         if let Some(kever) = self.kever() {
//             if let Some(prefixer) = kever.prefixer() {
//                 if prefixer.is_transferable() {
//                     let seal = if last {
//                         eventing::SealLast {
//                             i: prefixer.qb64(),
//                         }
//                     } else {
//                         eventing::SealEvent {
//                             i: prefixer.qb64(),
//                             s: format!("{:x}", kever.last_est().map(|e| e.s).unwrap_or(0)),
//                             d: kever.last_est().map(|e| e.d.clone()).unwrap_or_default(),
//                         }
//                     };
// 
//                     let sigers = self.sign(&serder.raw(), None, true, None, None)?;
//                     return eventing::messagize(serder, Some(sigers), None, Some(seal), pipelined);
//                 }
//             }
//         }
// 
//         let cigars = self.sign(&serder.raw(), None, false, None, None)?;
//         eventing::messagize(serder, None, Some(cigars), None, pipelined)
//     }
// 
//     /// Make end role message
//     pub fn make_end_role(
//         &self,
//         eid: String,
//         role: Roles,
//         stamp: Option<String>,
//     ) -> Result<Vec<u8>, KERIError> {
//         if let Some(pre) = &self.pre {
//             let mut data = HashMap::new();
//             data.insert("cid".to_string(), serde_json::Value::String(pre.clone()));
//             data.insert("role".to_string(), serde_json::Value::String(role.to_string()));
//             data.insert("eid".to_string(), serde_json::Value::String(eid));
// 
//             let route = "/end/role/add";
//             let serder = eventing::reply(route, data, stamp)?;
//             self.endorse(&serder, false, true)
//         } else {
//             Err(KERIError::ValueError("No prefix set for habitat".to_string()))
//         }
//     }
// 
//     /// Make location scheme message
//     pub fn make_loc_scheme(
//         &self,
//         url: String,
//         eid: Option<String>,
//         scheme: Schemes,
//         stamp: Option<String>,
//     ) -> Result<Vec<u8>, KERIError> {
//         let eid = eid.or_else(|| self.pre.clone())
//             .ok_or_else(|| KERIError::ValueError("No EID available".to_string()))?;
// 
//         let mut data = HashMap::new();
//         data.insert("eid".to_string(), serde_json::Value::String(eid));
//         data.insert("scheme".to_string(), serde_json::Value::String(scheme.to_string()));
//         data.insert("url".to_string(), serde_json::Value::String(url));
// 
//         let serder = eventing::reply("/loc/scheme", data, stamp)?;
//         self.endorse(&serder, false, true)
//     }
// 
//     /// Check if this habitat can act as a witness
//     pub fn witnesser(&self) -> bool {
//         true
//     }
// }
// 
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::keri::db::dbing::LMDBer;
//     use std::collections::HashMap;
// 
//     #[test]
//     fn test_base_hab_new() -> Result<(), KERIError> {
//         // This is a basic test structure - you'd need to implement proper mocks
//         // for the various components
// 
//         let name = Some("test_hab".to_string());
//         let ns = Some("test_ns".to_string());
//         let temp = Some(true);
// 
//         // In a real test, you'd create proper instances of all the required components
//         // For now, this shows the expected structure
// 
//         assert_eq!(name.as_ref().unwrap(), "test_hab");
//         assert_eq!(ns.as_ref().unwrap(), "test_ns");
//         assert_eq!(temp.unwrap(), true);
// 
//         Ok(())
//     }
// }