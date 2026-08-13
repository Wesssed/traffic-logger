use colored::{Colorize, control};
use std::{collections::HashMap, eprintln, format, println, vec};
use windivert::{WinDivert, prelude::WinDivertFlags};
trait Process {
    fn update_procs(&mut self);
    fn proc_name(&mut self, pid: u32) -> &str;
    fn find_proc_name<'a>(&mut self, proc_list: &'a mut HashMap<u32, String>, pid: u32) -> &'a str;
}

impl Process for sysinfo::System {
    fn update_procs(&mut self) {
        self.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            sysinfo::ProcessRefreshKind::nothing(),
        );
    }
    /// high-cost
    fn proc_name(&mut self, pid: u32) -> &str {
        self.update_procs();
        let pid_s = sysinfo::Pid::from(pid as usize);

        if let Some(process) = self.process(pid_s) {
            process.name().to_str().unwrap()
        } else {
            "unknown-process"
        }
    }
    /// optimised
    fn find_proc_name<'a>(&mut self, proc_list: &'a mut HashMap<u32, String>, pid: u32) -> &'a str {
        proc_list
            .entry(pid)
            .or_insert_with(|| self.proc_name(pid).into())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    let _ = control::set_virtual_terminal(true);

    let flags = WinDivertFlags::new().set_sniff();

    let handle = WinDivert::flow("true", 0, flags)?;

    let mut buffer: Vec<u8> = vec![];

    let mut sys = sysinfo::System::new_all();
    let mut process_names: HashMap<u32, String> = HashMap::new();

    loop {
        match handle.recv(Some(&mut buffer)) {
            Ok(packet) => {
                let pid = packet.address.process_id();
                let protocol = match packet.address.protocol() {
                    1 => "ICMP",
                    5 => "STREAM",
                    6 => "TCP",
                    17 => "UDP",
                    41 => "IPV6",
                    47 => "GRE",
                    50 => "ESP",
                    58 => "ICMPV6",
                    _ => "Other",
                };
                let dest_mark = if packet.address.outbound() {
                    &"--->".blue()
                } else {
                    &"<---".green()
                };
                let resource = format!(
                    "{}:{}",
                    packet.address.remote_address(),
                    packet.address.remote_port()
                );

                let proc_name = sys.find_proc_name(&mut process_names, pid);
                println!(
                    "[{}] [{}] {} [{}] {} {}",
                    chrono::Local::now().format("%H:%M:%S"),
                    protocol.green(),
                    proc_name.yellow(),
                    pid,
                    dest_mark,
                    resource
                );
            }
            Err(e) => {
                eprintln!("Error recieve packet: {e}");
                continue;
            }
        }
    }
}
