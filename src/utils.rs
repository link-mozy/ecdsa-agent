use log::{error, info};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::{
    fs::{remove_file, write},
    process,
};

use crate::common::Config;

pub fn is_file_lock_exist(port: &str) -> bool {
    let lock_path = lock_file_path(port);
    info!("lock_path: {:?}", lock_path.clone().as_path());
    Path::new(lock_path.as_path()).exists()
}

pub fn check_process_is_running_by_pid(port: &str) -> Option<u32> {
    let lock_path = lock_file_path(port).to_str().unwrap().to_string();
    let pid = read_pid(lock_path);
    if pid == 0 {
        None
    } else {
        let pid_str = pid.to_string();
        let args = vec!["-p", &pid_str, "-o", "pid="];
        let ps_cmd_out = process::Command::new("ps")
            .args(args)
            .output()
            .expect("failed to execute ps -p");
        if ps_cmd_out.status.success() {
            if String::from_utf8(ps_cmd_out.stdout)
                .unwrap()
                .contains(&pid_str.to_string())
            {
                Some(pid)
            } else {
                None
            }
        } else {
            None
        }
    }
}

pub fn write_pid_into_file_lock(port: &str, pid: &Vec<u8>) -> Result<(), anyhow::Error> {
    let lock_path = lock_file_path(port);
    let result = write(lock_path, pid);
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow::Error::msg(e.to_string())),
    }
}

pub fn del_file_lock(port: &str) {
    let lock_path = lock_file_path(port);
    match remove_file(lock_path) {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e);
        }
    }
}

pub fn lock_file_path(port: &str) -> PathBuf {
    let path = format!(".fil_ecdsa_agt_server_{}.lock", port);
    dirs::home_dir().unwrap().join(path)
}

pub fn read_pid(path: String) -> u32 {
    match File::open(path) {
        Ok(data) => {
            let mut buf_reader = BufReader::new(data);
            let mut contents = String::new();
            buf_reader
                .read_to_string(&mut contents)
                .expect("read pid failed");
            contents
                .parse::<u32>()
                .expect("parse pid error from pid file")
        }
        Err(_) => 0,
    }
}

pub fn get_config(path: String) -> Config {
    let config_file = std::fs::File::open(path.clone()).expect(&format!("Could not open {path} file."));
    serde_yaml::from_reader(config_file).expect("Could not read Config values.")
}