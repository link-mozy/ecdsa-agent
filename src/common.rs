#![allow(dead_code)]
use std::{
    str::FromStr,
    time::Duration,
    thread,
};
use aes_gcm::{
    Nonce,
    Aes256Gcm,
    aead::{Aead, NewAead},
};
use tokio::{
    runtime::Handle,
    task,
};

use log::{info, debug};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::ecdsa_agent_grpc::{InfoAgent, GetKeyRequest, BaseResponse};
use crate::ecdsa_agent_grpc::ecdsa_agent_service_client::EcdsaAgentServiceClient;
use crate::ecdsa_manager_grpc::{SetRequest, GetRequest};
use crate::ecdsa_manager_grpc::ecdsa_manager_service_client::EcdsaManagerServiceClient;

pub type Key = String;

#[allow(dead_code)]
pub const AES_KEY_BYTES_LEN: usize = 32;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: Key,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ResponseMsg {
    pub status: String,
    pub value: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AgentResponse {
    pub party_num: u16,
    pub msg: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub port: u32,
    pub manager_url: String,
    pub keyfile_path: String,
}

// Config file default Content
impl Default for Config {
    fn default() -> Self {
        Config {
            port: 4501,
            manager_url: "127.0.0.1:4500".to_string(),
            keyfile_path: "key.store".to_string(),
        }
    }
}

#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {
    let aes_key = aes_gcm::Key::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure!");

    AEAD {
        ciphertext,
        tag: nonce.to_vec(),
    }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
    let aes_key = aes_gcm::Key::from_slice(key);
    let nonce = Nonce::from_slice(&aead_pack.tag);
    let gcm = Aes256Gcm::new(aes_key);

    let out = gcm.decrypt(nonce, aead_pack.ciphertext.as_slice());
    out.unwrap()
}

pub async fn set(url: &str, key: &str, value: &str) -> String {
    let clinet = EcdsaManagerServiceClient::connect(format!("http://{}", url)).await;
    let request = tonic::Request::new(SetRequest {
        key: key.to_string(),
        value: value.to_string(),
    });
    info!("set(key: {:?}) call", key);
    let response = clinet.expect("EcdsaManagerServiceClient Connect Error.").set(request).await;
    response.expect("EcdsaManagerServiceClient get error.").into_inner().msg
}

pub async fn get(url: &str, key: &str) -> ResponseMsg {
    let clinet = EcdsaManagerServiceClient::connect(format!("http://{}", url)).await;
    let request = tonic::Request::new(GetRequest {
        key: key.to_string(),
    });
    info!("get(key: {}) call", key);
    let response = clinet.expect("EcdsaManagerServiceClient connect error.").get(request).await;
    let msg = response.expect("EcdsaManagerServiceClient get error.").into_inner().msg;
    serde_json::from_str(&msg).expect("response parse error.")
}

pub fn broadcast(
    url: &str,
    party_num: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> String {
    let key = format!("{}-{}-{}", party_num, round, sender_uuid);
    info!("broadcast(key: {}) call", key);
    task::block_in_place(|| {
        Handle::current().block_on(set(&url, &key, &data))
    })
}

pub async fn poll_for_broadcasts (
    url: &str,
    party_num: u16,
    info_agents: Vec<InfoAgent>, // n: u16, // PARTIES
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();

    for (_, info_agent) in info_agents.iter().enumerate() {
        let agent_party_num = <u16 as FromStr>::from_str(&info_agent.party_num).unwrap();
        if agent_party_num != party_num {
            let key = format!("{}-{}-{}", agent_party_num, round, sender_uuid);
            loop {
                thread::sleep(delay);
                let msg: ResponseMsg = get(&url, &key).await;
                if msg.status == "success" {
                    ans_vec.push(msg.value);
                    println!("[{:?}] party {:?} => party {:?}", round, agent_party_num, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}

pub fn poll (
    url: &str,
    party_num: u16,
    info_agents: Vec<InfoAgent>, // n: u16, // PARTIES
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    task::block_in_place( || {
        Handle::current().block_on(
            poll_for_broadcasts(&url, party_num, info_agents, delay, &round, sender_uuid)
        )
    })
}

pub fn get_aeads (
    party_num: u16,
    info_agents: Vec<InfoAgent>,
    round: &str,
    delay: Duration,
    sender_uuid: String,
) -> Vec<AEAD> {
    let tries_count: usize = 10;
    let other_agent_values_len: usize = info_agents.len() - 1;

    for idx in 0..tries_count {
        println!("[debug] P2P 통신 시도: {:?}", idx);
        thread::sleep(delay);
        let mut success_count = 0;
        let mut ans_response_vec = get_value_to_agents(
                                    party_num.try_into().unwrap(), 
                                    info_agents.clone(), 
                                    round.clone(), 
                                    sender_uuid.clone());
        ans_response_vec.sort_by(|a, b| a.party_num.cmp(&b.party_num));
        let aead_vec: Vec<AEAD> = ans_response_vec.iter().map(|response| {
            let msg: ResponseMsg = serde_json::from_str(&response.msg).unwrap();
            let status = msg.status;
            let value = msg.value;
            let aead: AEAD = serde_json::from_str(&value).unwrap();
            if "success" == status {
                success_count += 1;
                println!("[deubg] GetKey Success! (count: {:?})", success_count);
            }
            aead
        }).collect();

        if other_agent_values_len == success_count {
            println!("[deubg] 모든 통신 성공! (Agent 수: {:?}, 성공 횟수: {:?})", other_agent_values_len, success_count);
            return aead_vec;
        }
        // println!("[debug] ans_vec_aead : {:?}", ans_vec_aead)
    }
    // 실패했을 경우 빈 Vec 리턴
    Vec::new()
}

pub fn get_value_to_agents(
    party_num: u16,
    info_agents: Vec<InfoAgent>,
    round: &str,
    sender_uuid: String,
) -> Vec<AgentResponse> {
    debug!("arg::party_num{:?})", party_num);
    debug!("arg::info_agents{:?})", info_agents);
    debug!("arg::round{:?})", round);
    debug!("arg::sender_uuid{:?})", sender_uuid);
    let mut ans_vec = Vec::new();
    let other_agent_len = info_agents.len() - 1;
    let (sender, receiver) = std::sync::mpsc::channel();

    for (idx, info_agent) in info_agents.iter().enumerate() {
        let agent_party_num = u16::from_str(&info_agent.party_num).unwrap();
        if party_num != agent_party_num {
            let agent_url = info_agent.url.clone();
            let key = format!(
                "{}-{}-{}-{}", 
                agent_party_num, 
                party_num,
                round,
                sender_uuid.clone()
            );
            let sender_new = sender.clone();
            task::spawn(async move {
                let response = get_value_to_agent(&agent_url, &key).await;
                let msg = response.unwrap().msg;
                let result = AgentResponse{party_num: agent_party_num, msg: msg};
                sender_new.send(result).unwrap();
            });
        }
    }

    for idx in 0..other_agent_len {
        ans_vec.push(receiver.recv_timeout(Duration::from_secs(5)).unwrap());
        // ans_vec.push(receiver.recv().unwrap());
    }

    ans_vec
}

pub async fn get_value_to_agent(
    url: &str,
    key: &str,
) -> Result<BaseResponse, Box<dyn std::error::Error>> {
    debug!("arg(url: {:?}, key: {:?})", url, key);
    let mut client = EcdsaAgentServiceClient::connect(format!("http://{}", url))
                                                        .await.expect("agent connect error");
    let request = tonic::Request::new(GetKeyRequest {
        key: key.to_string(),
    });
    let response = client.get_key(request).await?.into_inner();
    Ok(response)
}