#![allow(dead_code)]

use std::{env, thread, time, time::Duration};

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::ecdsa_agent_grpc::InfoAgent;
use crate::ecdsa_manager_grpc::SetRequest;
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

// #[derive(Debug, Serialize, Deserialize)]
// pub struct InfoAgent {
//     pub party_num: u32,
//     pub url: String,
// }

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

pub fn postb<T>(client: &Client, path: &str, body: T) -> Option<String>
where
    T: serde::ser::Serialize,
{
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8001".to_string());
    let retries = 3;
    let retry_delay = time::Duration::from_millis(250);
    for _i in 1..retries {
        let res = client
            .post(&format!("{}/{}", addr, path))
            .json(&body)
            .send();

        if let Ok(mut res) = res {
            return Some(res.text().unwrap());
        }
        thread::sleep(retry_delay);
    }
    None
}

pub async fn set(url: &str, key: &str, value: &str) -> String {
    let clinet = EcdsaManagerServiceClient::connect(format!("http://{}", url)).await;
    let request = tonic::Request::new(SetRequest {
        key: key.to_string(),
        value: value.to_string(),
    });
    let response = clinet.expect("EcdsaManagerServiceClient Connect Error.").set(request).await;
    response.expect("REASON").into_inner().msg
}

// pub fn broadcast(
//     client: &Client,
//     party_num: u16,
//     round: &str,
//     data: String,
//     sender_uuid: String,
// ) -> Result<(), ()> {
//     let key = format!("{}-{}-{}", party_num, round, sender_uuid);
//     let entry = Entry { key, value: data };

//     let res_body = postb(client, "set", entry).unwrap();
//     serde_json::from_str(&res_body).unwrap()
// }

pub fn broadcast(
    url: &str,
    party_num: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> String {
    let key = format!("{}-{}-{}", party_num, round, sender_uuid);
    // let entry = Entry { key: key.clone(), value: data.clone() };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(set(&url, &key, &data))
}

pub fn sendp2p(
    client: &Client,
    party_from: u16,
    party_to: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<(), ()> {
    let key = format!("{}-{}-{}-{}", party_from, party_to, round, sender_uuid);

    let entry = Entry { key, value: data };

    let res_body = postb(client, "set", entry).unwrap();
    serde_json::from_str(&res_body).unwrap()
}

pub fn poll_for_broadcasts(
    client: &Client,
    party_num: u16,
    n: u16, // PARTIES
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}", i, round, sender_uuid);
            let index = Index { key };
            loop {
                // add delay to allow the server to process request:
                thread::sleep(delay);
                let res_body = postb(client, "get", index.clone()).unwrap();
                let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                if let Ok(answer) = answer {
                    ans_vec.push(answer.value);
                    println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}

pub fn poll_for_broadcasts_new (
    url: &str,
    party_num: u16,
    info_agents: Vec<InfoAgent>, // n: u16, // PARTIES
    round: &str,
    data: String,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for info_agent in info_agents.iter().enumerate() {
        println!("info_agnet: {:?}", info_agent)
    }
    ans_vec
}

pub fn poll_for_p2p(
    client: &Client,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}-{}", i, party_num, round, sender_uuid);
            let index = Index { key };
            loop {
                // add delay to allow the server to process request:
                thread::sleep(delay);
                let res_body = postb(client, "get", index.clone()).unwrap();
                let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                if let Ok(answer) = answer {
                    ans_vec.push(answer.value);
                    println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}