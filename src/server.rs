use crate::error;
use crate::common::{Key, broadcast};
use crate::ecdsa_agent_grpc::{RunKeygenRequest, GetKeyRequest, BaseResponse, InfoAgent};
use crate::ecdsa_agent_grpc::ecdsa_agent_service_server::{EcdsaAgentService, EcdsaAgentServiceServer};
use crate::status::{ServerStatus};

use std::collections::HashMap;
use std::str::FromStr;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use log::info;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{oneshot};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use futures::future::FutureExt;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters,
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
        let parties: u16 = <u16 as FromStr>::from_str(&req.threshold).unwrap();
        let info_agents: Vec<InfoAgent> = req.info_agents;
        let mut si = self.server_info.lock().unwrap();
        let mut hm = si.storage.write().unwrap();
        hm.insert(uuid.clone(), party_number.to_string());

        println!("debug::run_keygen::request info:");
        println!("uuid: {:?}", uuid);
        println!("party_number: {:?}", party_number);
        println!("threshold: {:?}", threshold);
        println!("parties: {:?}", parties);
        println!("info_agents: {:?}", info_agents);

        let server_url = "127.0.0.1:4500";

        //////////// start ///////////// 
        // addr: &String, keysfile_path: &String, params: &Vec<&str>
        // let client = Client::new();

        // delay:
        // let delay = time::Duration::from_millis(25);
        // let params = Parameters {
        //     threshold: THRESHOLD,
        //     share_count: PARTIES,
        // };
        //signup:
        // let tn_params = Params {
        //     threshold: THRESHOLD.to_string(),
        //     parties: PARTIES.to_string(),
        // };
        // let (party_num_int, uuid) = match keygen_signup(&addr, &client, &tn_params).unwrap() {
        //     PartySignup { number, uuid } => (number, uuid),
        // };
        let party_keys = Keys::create(party_number as usize);
        let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

        // send commitment to ephemeral public keys, get round 1 commitments of other parties
        // let addr = "127.0.0.1:8001";
        // let client = Client::new();
        // assert!(broadcast(
        //     &addr,
        //     &client,
        //     party_num,
        //     "round1",
        //     serde_json::to_string(&bc_i).unwrap(),
        //     uuid.clone(),
        // )
        // .is_ok());
        broadcast(
            &server_url, 
            party_number.try_into().unwrap(), 
            "round1", 
            serde_json::to_string(&bc_i).unwrap(),
            uuid.clone(),
        );
        // let round1_ans_vec = poll_for_broadcasts(
        //     &addr,
        //     &client,
        //     party_num_int,
        //     PARTIES,
        //     delay,
        //     "round1",
        //     uuid.clone(),
        // );

        
        println!("run_keygent call!! uuid: {:?}, party_number: {:?}", uuid, party_number);
        let msg = format!("success! (uuid: {uuid}, party_number: {party_number})");
        Ok(Response::new(BaseResponse { msg: msg.to_string() }))
    }

    async fn get_aead_pack (
        &self,
        request: Request<GetKeyRequest>
    ) -> Result<Response<BaseResponse>, Status> {
        let req = request.into_inner();
        let key = req.key;

        let mut si = self.server_info.lock().unwrap();
        let mut hm = si.storage.read().unwrap();
        match hm.get(&key) {
            Some(v) => {
                let msg = format!("success! (key: {key}, value: {v})");
                Ok(Response::new(BaseResponse { msg: msg.to_string() }))
            }
            None => {
                let msg = format!("fail! (key: {key})");
                Ok(Response::new(BaseResponse { msg: msg.to_string() }))
            }
        }
    }

    async fn get_keygen_info (
        &self,
        request: Request<GetKeyRequest>
    ) -> Result<Response<BaseResponse>, Status> {
        let req = request.into_inner();
        let key = req.key;

        println!("get_keygen_info call!! key: {:?}", key);
        let msg = "success! (key: {key})";
        Ok(Response::new(BaseResponse { msg: msg.to_string() }))
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