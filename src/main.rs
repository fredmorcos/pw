#![warn(clippy::all)]

use std::env;
use std::fmt::{self, Debug};
use std::fs;
use std::io;
use std::process;

static PASSFILE: &str = "/home/fred/Documents/Important/Passwords/Passwords.txt";

enum Error {
    MissingCommand,
    UnknownCommand(String),
    PassFile(io::Error),
    PWGenSpawn(io::Error),
    PWGenWait(io::Error),
    PWGenErr(i32),
    PWGenDied,
    Mismatch(usize, String),
    GetArgs,
}

impl Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::MissingCommand => write!(f, "missing command: check, gen, get"),
            Error::UnknownCommand(cmd) => write!(f, "unknown command: {}", cmd),
            Error::PassFile(err) => write!(f, "error reading password file: {}", err),
            Error::PWGenSpawn(err) => write!(f, "error running pwgen: {}", err),
            Error::PWGenWait(err) => write!(f, "could not wait on pwgen: {}", err),
            Error::PWGenErr(code) => write!(f, "pwgen failed with code {}", code),
            Error::PWGenDied => write!(f, "pwgen died from a signal"),
            Error::Mismatch(n, key) => write!(f, "found {} matches for {}", n, key),
            Error::GetArgs => write!(f, "get expects 2 arguments: key and format string"),
        }
    }
}

fn main() -> Result<(), Error> {
    let mut args = env::args();
    let _cmd = args.next();
    let cmd = args.next().ok_or(Error::MissingCommand)?;
    let data = fs::read_to_string(PASSFILE).map_err(Error::PassFile)?;
    let lines = data
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        })
        .map(|line| line.split_whitespace().collect::<Vec<&str>>());
    let valid_lines = lines.clone().filter(|line| line[0] == "+");
    match cmd.as_str() {
        "check" => {
            let valid_pws = valid_lines.count();
            let invalid_pws = lines.clone().filter(|line| line[0] == "-").count();
            let change_pws = lines.clone().filter(|line| line[0] == "*").count();
            println!(
                "{} current passwords, \
                 {} inactive accounts, \
                 {} passwords need changing",
                valid_pws, invalid_pws, change_pws
            );
        }
        "gen" => {
            let exit_status = process::Command::new("pwgen")
                .args(&["-c", "-n", "-y", "-s", "-B", "-1", "34", "1"])
                .spawn()
                .map_err(Error::PWGenSpawn)?
                .wait()
                .map_err(Error::PWGenWait)?;
            if !exit_status.success() {
                if let Some(code) = exit_status.code() {
                    return Err(Error::PWGenErr(code));
                } else {
                    return Err(Error::PWGenDied);
                }
            }
        }
        "get" => {
            let acc_name = args.next().ok_or(Error::GetArgs)?;
            let text = args.next().ok_or(Error::GetArgs)?;
            let matched_accs = valid_lines.filter(|line| line[1] == acc_name);
            let n_matches = matched_accs.clone().count();
            if n_matches != 1 {
                return Err(Error::Mismatch(n_matches, acc_name));
            }
            let acc = &matched_accs.collect::<Vec<Vec<&str>>>()[0];
            let text = text
                .replace("%L", acc[2])
                .replace("%U", acc[3])
                .replace("%P", acc[4]);
            println!("{}", text);
        }
        _ => return Err(Error::UnknownCommand(cmd)),
    }

    Ok(())
}
