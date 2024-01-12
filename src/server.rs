use crate::error;
use crate::common::{Key, AEAD, broadcast, poll, aes_encrypt, get_aeads, aes_decrypt};
use crate::ecdsa_agent_grpc::{RunKeygenRequest, GetKeyRequest, BaseResponse, InfoAgent};
use crate::ecdsa_agent_grpc::ecdsa_agent_service_server::{EcdsaAgentService, EcdsaAgentServiceServer};
use crate::status::{ServerStatus};

use std::collections::HashMap;
use std::str::FromStr;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use std::fs;
use log::info;
use serde_json::json;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{oneshot};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use futures::future::FutureExt;
use paillier::EncryptionKey;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters,
};

use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
    elliptic::curves::secp256_k1::{FE, GE}
};



pub const SERVER_LOCK_TIME_OUT_DEFAULT: Duration = Duration::from_secs(10);
pub const SERVER_TASK_GET_BACK_TIME_OUT_DEFAULT: Duration = Duration::from_secs(60);
pub const SERVER_EXIT_TIME_OUT_AFTER_TASK_DONE_DEFAULT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub struct EcdsaAgentServer {
    pub server_info: Arc<Mutex<ServerInfo>>,
    task_run_tx: UnboundedSender<String>,
}

#[derive(Debug)]
pub struct ServerInfo {
    pub status: ServerStatus,
    pub storage: RwLock<HashMap<Key, String>>,
    pub last_update_time: Instant,
    pub server_lock_time_out: Duration,
    pub server_task_get_back_time_out: Duration,
    pub server_exit_time_out_after_task_done: Duration,
    pub error: String,
}

impl Default for ServerInfo {
    fn default() -> Self {
        ServerInfo {
            status: ServerStatus::default(),
            storage: RwLock::new(HashMap::new()),
            last_update_time: Instant::now(),
            server_lock_time_out: SERVER_LOCK_TIME_OUT_DEFAULT,
            server_task_get_back_time_out: SERVER_TASK_GET_BACK_TIME_OUT_DEFAULT,
            server_exit_time_out_after_task_done: SERVER_EXIT_TIME_OUT_AFTER_TASK_DONE_DEFAULT,
            error: String::default(),
        }
    }
}

impl EcdsaAgentServer {
    pub fn new(task_run_tx: UnboundedSender<String>) -> Self {
        EcdsaAgentServer { 
            server_info: Arc::new(Mutex::new(ServerInfo::default())), 
            task_run_tx,
        }
    }

    pub fn set_time_out(
        &self,
        server_lock_time_out: Duration,
        server_task_get_back_time_out: Duration,
        server_exit_time_out_after_task_done: Duration,
    ) -> anyhow::Result<()> {
        let mut si = match self.server_info.lock() {
            Ok(s) => s,
            Err(e) => {
                return Err(anyhow::Error::msg(e.to_string()));
            }
        };
        si.server_lock_time_out = server_lock_time_out;
        si.server_task_get_back_time_out = server_task_get_back_time_out;
        si.server_exit_time_out_after_task_done = server_exit_time_out_after_task_done;
        Ok(())
    }

    pub fn set_server_lock_time_out(
        &self,
        time_out: Duration
    ) -> anyhow::Result<()> {
        let mut si = match self.server_info.lock() {
            Ok(s) => s,
            Err(e) =>  {
                return Err(anyhow::Error::msg(e.to_string()));
            }
        };
        si.server_lock_time_out = time_out;
        Ok(())
    }
    
    pub fn set_server_task_get_back_time_out(
        &self,
        time_out: Duration
    ) -> anyhow::Result<()> {
        let mut si = match self.server_info.lock() {
            Ok(s) => s,
            Err(e) => {
                return Err(anyhow::Error::msg(e.to_string()));
            }
        };
        si.server_task_get_back_time_out = time_out;
        Ok(())
    }
    
    pub fn set_server_exit_time_out_after_task_done(
        &self,
        time_out: Duration
    ) -> anyhow::Result<()> {
        let mut si = match self.server_info.lock() {
            Ok(s) => s,
            Err(e) => {
                return Err(anyhow::Error::msg(e.to_string()));
            }
        };
        si.server_exit_time_out_after_task_done = time_out;
        Ok(())
    }
    
    fn do_task(
        &self
    ) -> Result<(), Status> {
        let mut si = match self.server_info.lock() {
            Ok(s) => s,
            Err(e) => {
                return Err(Status::aborted(e.to_string()));
            }
        };

        if si.status == ServerStatus::Locked {
            si.status = ServerStatus::Working;
            si.last_update_time = Instant::now();
            match self.task_run_tx.send("ok".to_string()) {
                Ok(_) => Ok(()),
                Err(s) => Err(Status::cancelled(s.0)),
            }
        } else {
            match si.status {
                ServerStatus::Locked => Err(Status::cancelled(
                    "server was locked by another task, can not be used now",
                )),
                ServerStatus::Free => Err(Status::cancelled(
                    "server should be locked until task is executed",
                )),
                ServerStatus::Working => Err(Status::cancelled(
                    "server is working on another task, can not be used now",
                )),
                ServerStatus::Unknown => {
                    Err(Status::cancelled("server is Unknown, can not be used now"))
                }
            }
        }
    }
    
    fn lock_server_if_free(
        &self
    ) -> Result<ServerStatus, Status> {
        let mut si = match self.server_info.lock() {
            Ok(s) => s,
            Err(e) => {
                return Err(Status::aborted(e.to_string()));
            }
        };

        match si.status {
            ServerStatus::Free => {
                si.status = ServerStatus::Locked;
                si.last_update_time = Instant::now();
                Ok(ServerStatus::Free)
            }
            ServerStatus::Locked => {
                if Instant::now().duration_since(si.last_update_time) > si.server_lock_time_out {
                    si.status = ServerStatus::Locked;
                    si.last_update_time = Instant::now();
                    Ok(ServerStatus::Free)
                } else {
                    Ok(ServerStatus::Locked)
                }
            }
            ServerStatus::Working => {
                if Instant::now().duration_since(si.last_update_time) >= si.server_task_get_back_time_out {
                    si.status = ServerStatus::Locked;
                    si.last_update_time = Instant::now();
                    Ok(ServerStatus::Free)
                } else {
                    Ok(ServerStatus::Working)
                }
            }
            ServerStatus::Unknown => Ok(ServerStatus::Unknown),
        }
    }
    
    fn get_task_result(
        &self
    ) -> Result<Vec<u8>, Status> {
        let mut si = match self.server_info.lock() {
            Ok(s) => s,
            Err(e) => {
                return Err(Status::aborted(e.to_string()));
            }
        };

        if si.status == ServerStatus::Working {
            println!("get_task_result call!!");
            Ok(vec![])
        } else {
            Err(Status::cancelled(
                anyhow::Error::from(error::Error::NoTaskRunningOnSever).to_string(),
            ))
        }
    }
    
    fn unlock(
        &self
    ) -> Result<(), Status> {
        let mut si = match self.server_info.lock() {
            Ok(s) => s,
            Err(e) => {
                return Err(Status::aborted(e.to_string()));
            }
        };

        if si.status == ServerStatus::Free {
            Err(Status::cancelled("server is already Free"))
        } else {
            if si.status == ServerStatus::Locked {
                println!("unlock call!!");
                Ok(())
            } else {
                Err(Status::cancelled(
                    "this operation just used to unlock a server in status Locked",
                ))
            }
        }
    }
}

#[tonic::async_trait]
impl EcdsaAgentService for EcdsaAgentServer {
    async fn run_keygen (
        &self,
        request: Request<RunKeygenRequest>
    ) -> Result<Response<BaseResponse>, Status> {
        let req = request.into_inner();
        let uuid = req.uuid;
        let party_number: i32 = <i32 as FromStr>::from_str(&req.party_number).unwrap();
        let threshold: u16 = <u16 as FromStr>::from_str(&req.threshold).unwrap();
        let parties: u16 = <u16 as FromStr>::from_str(&req.parties).unwrap();
        let info_agents: Vec<InfoAgent> = req.info_agents;
        { // mutext open
            let si = self.server_info.lock().unwrap();
            let mut hm = si.storage.write().unwrap();
            hm.insert(uuid.clone(), party_number.to_string());
        } // mutext close

        info!("run_keygen call. [uuid: {:?}]", uuid);
        println!("debug::run_keygen::request info:");
        println!("uuid: {:?}", uuid);
        println!("party_number: {:?}", party_number);
        println!("threshold: {:?}", threshold);
        println!("parties: {:?}", parties);
        println!("info_agents: {:?}", info_agents);

        // TODO. Configuration 사용하도록 수정 필요.
        let server_url = "127.0.0.1:4500";

        // delay:
        let delay = Duration::from_millis(500);
        let params = Parameters {
            threshold: threshold,
            share_count: parties,
        };
        let party_keys = Keys::create(party_number as usize);
        let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

        // send commitment to ephemeral public keys, get round 1 commitments of other parties
        info!("round 1 start.");
        broadcast(
            &server_url, 
            party_number.try_into().unwrap(), 
            "round1", 
            serde_json::to_string(&bc_i).unwrap(),
            uuid.clone(),
        );
        
        let round1_ans_vec = poll(
            &server_url, 
            party_number.try_into().unwrap(), 
            info_agents.clone(), 
            delay, 
            "round1", 
            uuid.clone(),
        );

        let mut bc1_vec = round1_ans_vec
            .iter()
            .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
            .collect::<Vec<_>>();

        bc1_vec.insert(party_number as usize - 1, bc_i);
        info!("round 1 end.");

        // send ephemeral public keys and check commitments correctness
        info!("round 2 start.");
        broadcast(
            &server_url, 
            party_number.try_into().unwrap(), 
            "round2", 
            serde_json::to_string(&decom_i).unwrap(),
            uuid.clone(),
        );

        let round2_ans_vec = poll(
            &server_url, 
            party_number.try_into().unwrap(), 
            info_agents.clone(), 
            delay, 
            "round2", 
            uuid.clone(),
        );

        let mut j = 0;
        let mut point_vec: Vec<GE> = Vec::new();
        let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
        let mut enc_keys: Vec<BigInt> = Vec::new();
        for i in 1..=parties {
            if i as i32 == party_number {
                point_vec.push(decom_i.y_i);
                decom_vec.push(decom_i.clone());
            } else {
                let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec[j]).unwrap();
                point_vec.push(decom_j.y_i);
                decom_vec.push(decom_j.clone());
                enc_keys.push((decom_j.y_i.clone() * party_keys.u_i).x_coor().unwrap());
                j = j + 1;
            }
        }

        let (head, tail) = point_vec.split_at(1);
        let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

        let (vss_scheme, secret_shares, _index) = party_keys
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &params, &decom_vec, &bc1_vec,
            )
            .expect("invalid key");

        info!("round 2 end.");
        //////////////////////////////////////////////////////////////////////////////
        
        { // mutex open
            let si = self.server_info.lock().unwrap();
            let mut hm = si.storage.write().unwrap();
            let mut j = 0;
            for (k, i) in (1..=parties).enumerate() {
                if i as i32 != party_number {
                    // prepare encrypted ss for party i:
                    let key_i = BigInt::to_bytes(&enc_keys[j]);
                    let plaintext = BigInt::to_bytes(&secret_shares[k].to_big_int());
                    let aead_pack_i = aes_encrypt(&key_i, &plaintext);
                    // key format : {party_from}-{party_to}-{round}-{sender_uuid}
                    let key = format!("{}-{}-{}-{}", party_number, i, "round3", uuid);
                    println!("p2p(save) key: {:?}", key);
                    // value : serde_json::to_string(&aead_pack_i).unwrap()
                    hm.insert(key.clone(),serde_json::to_string(&aead_pack_i).unwrap());
                    j += 1;
                }
            }
        } // mutex close 
        
        let round3_ans_vec = get_aeads(
                                                party_number.try_into().unwrap(), 
                                                info_agents.clone(), 
                                                "round3", 
                                                delay, 
                                                uuid.clone());
        // println!("[debug] round3_ans_vec : {:?}", round3_ans_vec);
        let mut j = 0;
        let mut party_shares: Vec<FE> = Vec::new();
        for i in 1..=parties {
            if i as i32 == party_number {
                party_shares.push(secret_shares[(i - 1) as usize]);
            } else {
                let aead_pack: AEAD = round3_ans_vec[j].clone();
                let key_i = BigInt::to_bytes(&enc_keys[j]);
                // println!("key_i : {:?}", key_i);
                // println!("aead_pack : {:?}", aead_pack);
                let out = aes_decrypt(&key_i, aead_pack);
                let out_bn = BigInt::from_bytes(&out);
                let out_fe = ECScalar::from(&out_bn);
                party_shares.push(out_fe);

                j += 1;
            }
        }
        println!("[debug] round3 성공! party_shares : {:?}", party_shares);

        // round 4: send vss commitments
        info!("round 4 start.");
        broadcast(
            &server_url, 
            party_number.try_into().unwrap(), 
            "round4", 
            serde_json::to_string(&vss_scheme).unwrap(),
            uuid.clone(),
        );

        let round4_ans_vec = poll(
            &server_url, 
            party_number.try_into().unwrap(), 
            info_agents.clone(), 
            delay, 
            "round4", 
            uuid.clone(),
        );

        let mut j = 0;
        let mut vss_scheme_vec: Vec<VerifiableSS<GE>> = Vec::new();
        for i in 1..=parties {
            if i as i32 == party_number {
                vss_scheme_vec.push(vss_scheme.clone());
            } else {
                let vss_scheme_j: VerifiableSS<GE> = serde_json::from_str(&round4_ans_vec[j]).unwrap();
                vss_scheme_vec.push(vss_scheme_j);
                j += 1;
            }
        }

        let (shared_keys, dlog_proof) = party_keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &params,
                &point_vec,
                &party_shares,
                &vss_scheme_vec,
                party_number as usize,
            )
            .expect("invalid vss");
        
        info!("round 4 end.");

        // round 5: send dlog proof
        info!("round 5 start.");
        broadcast(
            &server_url, 
            party_number.try_into().unwrap(), 
            "round5", 
            serde_json::to_string(&dlog_proof).unwrap(),
            uuid.clone(),
        );

        let round5_ans_vec = poll(
            &server_url, 
            party_number.try_into().unwrap(), 
            info_agents.clone(), 
            delay, 
            "round5", 
            uuid.clone(),
        );

        let mut j = 0;
        let mut dlog_proof_vec: Vec<DLogProof<GE>> = Vec::new();
        for i in 1..=parties {
            if i as i32 == party_number {
                dlog_proof_vec.push(dlog_proof.clone());
            } else {
                let dlog_proof_j: DLogProof<GE> = serde_json::from_str(&round5_ans_vec[j]).unwrap();
                dlog_proof_vec.push(dlog_proof_j);
                j += 1;
            }
        }
        Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec).expect("bad dlog proof");
        info!("round 5 end.");

        //save key to file:
        let paillier_key_vec = (0..parties)
            .map(|i| bc1_vec[i as usize].e.clone())
            .collect::<Vec<EncryptionKey>>();

        let keygen_json = serde_json::to_string(&(
            party_keys,
            shared_keys,
            party_number,
            vss_scheme_vec,
            paillier_key_vec,
            y_sum,
        ))
        .unwrap();

        // TODO. 파일 저장 위치 받아와야 함.
        let keyfile_path = format!("key_{}.store", party_number);
        println!("Keys data written to file: {:?}", keyfile_path);
        fs::write(&keyfile_path, keygen_json).expect("Unable to save !");
        
        let msg = format!("success! (uuid: {uuid}, party_number: {party_number})");
        Ok(Response::new(BaseResponse { msg: msg.to_string() }))
    }

    async fn get_key (
        &self,
        request: Request<GetKeyRequest>
    ) -> Result<Response<BaseResponse>, Status> {
        let req = request.into_inner();
        let key = req.key;
        let si = self.server_info.lock().unwrap();
        let hm = si.storage.read().unwrap();
        match hm.get(&key) {
            Some(value) => {
                let msg = json!({"status": "success", "value": value});
                Ok(Response::new(BaseResponse { msg: msg.to_string() }))
            }
            None => {
                let msg = json!({"status": "fail", "value": ""});
                Ok(Response::new(BaseResponse { msg: msg.to_string() }))
            }
        }
    }
}

pub async fn run_server(
    server_exit_rx: oneshot::Receiver<String>,
    srv: EcdsaAgentServer,
    port: String,
) {
    let mut addr_s = "0.0.0.0:".to_string();
    addr_s += &port;
    let addr = addr_s.parse::<SocketAddr>().unwrap();
    info!("Server listening on {}", addr);
    Server::builder()
        .accept_http1(true)
        .add_service(EcdsaAgentServiceServer::new(srv))
        .serve_with_shutdown(addr, server_exit_rx.map(drop))
        .await
        .unwrap();
    info!("server stop listen")
}