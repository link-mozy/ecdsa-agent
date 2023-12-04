use clap::{App, Arg};
use ecdsa_agent::server::{SERVER_LOCK_TIME_OUT_DEFAULT, SERVER_TASK_GET_BACK_TIME_OUT_DEFAULT, SERVER_EXIT_TIME_OUT_AFTER_TASK_DONE_DEFAULT};
use ecdsa_agent::utils;
use std::process::exit;
use std::{env, process};
use log::{info, warn, error};
use ecdsa_agent::run::run;

fn main() {
    let cmds = App::new("ecdsa-agent")
        .author("tester")
        .version("0.0.1")
        .subcommands(vec![run_cmd(), stop_cmd()]);
    let mut _cmds = cmds.clone();
    let matches = cmds.get_matches();

    match matches.subcommand_name() {
        Some("run") => {
            env::set_var("RUST_BACKTRACE", "full");
            let run_matched = matches.subcommand_matches("run").unwrap();
            if run_matched.is_present("debug") {
                env::set_var("RUST_LOG", "debug");
            } else {
                env::set_var("RUST_LOG", "info");
            }

            fil_logger::init();
            let port = run_matched.value_of("port").unwrap().to_string();
            assert_eq!(can_run(), true); // 기존에 실행되고 있는 서비스가 있는지 확인
            run(port, 
                SERVER_LOCK_TIME_OUT_DEFAULT, 
                SERVER_TASK_GET_BACK_TIME_OUT_DEFAULT, 
                SERVER_EXIT_TIME_OUT_AFTER_TASK_DONE_DEFAULT)
        }
        Some("stop") => {
            let stop_matched = matches.subcommand_matches("stop").unwrap();
            let pid = stop_matched.value_of("pid").unwrap().to_string();
            stop(pid);
        }
        _ => {
            _cmds.print_help().unwrap();
            exit(1)
        }
    }

}

fn run_cmd() -> App<'static, 'static> {
    App::new("run").about("run ecdsa-agent").args(&[
        Arg::from_usage("-d, --debug 'print debug log'").required(false),
        Arg::from_usage("-p, --port==[PORT] 'specify server port'")
            .default_value("4501")
            .required(false),
    ])
}

fn stop_cmd() -> App<'static, 'static> {
    App::new("stop").about("stop ecdsa-agent").args(&[
        Arg::from_usage("-p, --pid=[PID] 'specify server pid'")
            .default_value("")
            .required(false),
    ])
}

fn stop(pid_s: String) {
    let mut pid;
    if pid_s == String::default() {
        pid = utils::read_pid(utils::lock_file_path().to_str().unwrap().to_string());
    } else {
        pid = pid_s.parse::<u32>().unwrap()
    }
    process::Command::new("kill").arg(pid.to_string()).output().unwrap();
}

fn can_run() -> bool {
    if utils::is_file_lock_exist() {
        warn!("file lock existed, will check process is_running by pid");
        if let Some(p) = utils::check_process_is_running_by_pid() {
            error!("process double run, old process still running, pid: {}", p);
            false
        } else {
            warn!("old process is not running, let's go on");
            true
        }
    } else {
        let pid = &process::id().to_string().as_bytes().to_vec();
        match utils::write_pid_into_file_lock(pid) {
            Ok(_) => {
                info!("write pid into lock file success");
                true
            }
            Err(e) => {
                error!("write pid into lock file failed with error: {}", e);
                false
            }
        }
    }
}