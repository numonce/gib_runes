use clap::{Arg, Command};
use colored::Colorize;
use process_memory::DataMember;
use process_memory::Memory;
use process_memory::Pid;
use process_memory::TryIntoProcessHandle;
use std::error::Error;
use std::mem;
use sysinfo::System;
use windows::Win32::{
    Foundation::HMODULE,
    System::{
        ProcessStatus::EnumProcessModules,
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

fn get_elden_ring_base(eldenring: u32) -> Result<usize, Box<dyn Error>> {
    unsafe {
        println!("{}", "[!] Getting handle to Elden Ring".yellow());
        let handle = match OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            false,
            eldenring,
        ) {
            Ok(h) => h,
            Err(_) => panic!("{}", "[x] Couldn't get handle to process.".red()),
        };
        println!("{} {:?}", "[+] Got Handle".green(), handle);
        println!(
            "{}",
            "[!] Enumerating process modules of Elden Ring...".yellow()
        );

        let mut modules = vec![HMODULE(0); 0]; // less `unsafe { ... }` than mem::zeroed()
        loop {
            let mut lpcbneeded = 0;
            let modules_size = mem::size_of_val(&modules[..]) as u32;
            match EnumProcessModules(handle, modules.as_mut_ptr(), modules_size, &mut lpcbneeded) {
                Ok(()) => {}
                Err(_) => panic!("{}", "[!] Unable to get process module.".red()),
            }
            let needed_modules = lpcbneeded as usize / mem::size_of::<HMODULE>();
            if needed_modules <= modules.len() {
                modules.truncate(needed_modules);
                break; // we got all the modules we needed
            } else {
                // we only got some of the modules, grow `modules` so we can try again:
                modules.reserve(needed_modules - modules.len()); // will request at least one additional capacity
                modules.resize(modules.capacity(), HMODULE(0)); // allow EnumProcessModules to use the entire size
            }
        }
        let base_addr = modules[0].0;
        println!("{} {:X}", "[+] Found base address at".green(), base_addr);
        Ok(base_addr as usize)
    }
}

fn get_elden_ring_pid() -> Result<u32, Box<dyn Error>> {
    println!("{}", "[!] Getting PID of Elden Ring".yellow());
    let mut s = System::new_all();
    s.refresh_all();
    let mut er = s.processes_by_exact_name("eldenring.exe").peekable();
    let er_process = er.peek();
    if er_process.is_none() {
        panic!("{}", "[x] Couldn't find Elden Ring. Is it running?".red());
    }
    let pid = er_process.unwrap().pid().as_u32();
    println!("{} {}", "[+] PID is".green(), pid.to_string().green());
    Ok(pid)
}

fn patch_runes(runes: u32, base_address: usize, pid: u32) -> Result<(), Box<dyn Error>> {
    println!("{}", "[!] Looking for runes...".yellow());
    unsafe {
        let handle = (pid as Pid).try_into_process_handle()?;
        let offsets: Vec<usize> = vec![0x3CDCDD8, 0x1e508, 0x10, 0x0, 0x580];
        let mut new_addr = base_address as u64;
        for i in 0..offsets.len() {
            let member = DataMember::new_offset(handle, vec![new_addr as usize + offsets[i]]);
            new_addr = match member.read() {
                Ok(value) => value,
                Err(e) => panic!("{}", e),
            };
        }
        new_addr += 0x6c;
        let runes_addr: DataMember<u32> = DataMember::new_offset(handle, vec![new_addr as usize]);
        println!(
            "{}{:X} {} {}",
            "[+] Found runes at ".green(),
            new_addr,
            "with value".green(),
            runes_addr.read()?
        );
        println!("{} {}", "[+] Patching with value".green(), &runes);
        runes_addr.write(&runes)?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let app = Command::new("gib runes")
        .about("This is a tool to patch runes for Elden Ring. Don't use this with anticheat on.")
        .version("1.0.0")
        .arg(
            Arg::new("runes")
                .long("runes")
                .short('r')
                .help("The amount of runes you want to have")
                .required(true),
        )
        .get_matches();
    let runes_str = app.get_one::<String>("runes").unwrap();
    let runes: u32 = runes_str.parse()?;
    let pid = get_elden_ring_pid()?;
    let base_addr = get_elden_ring_base(pid)?;
    patch_runes(runes, base_addr, pid)?;
    Ok(())
}
