#![warn(clippy::all)]

use log::{debug, info};
use std::fmt::{self, Debug};
use std::fs;
use std::io::{self, Read};
use std::process;
use structopt::StructOpt;
use thiserror::Error;

#[derive(Debug, StructOpt)]
enum Cmd {
    #[structopt(about = "Check and print password stats")]
    Check,
    #[structopt(name = "gen", about = "Generate a password")]
    Generate,
    #[structopt(about = "Retrieve a password")]
    Get {
        #[structopt(help = "Exact match for an account name")]
        account_name: String,
        #[structopt(help = "Format using %N = Name, %L = Link, %U = Username, %P = Password")]
        format: String,
    },
    #[structopt(name = "ls", about = "Search for passwords")]
    List {
        #[structopt(help = "Query for an account name")]
        query: String,
    },
}

#[derive(Debug, StructOpt)]
#[structopt(about = "Dumb Password Manager")]
struct Pw {
    #[structopt(short, long, parse(from_occurrences))]
    verbose: u8,
    #[structopt(subcommand)]
    command: Cmd,
}

static PASSFILE: &str = "/home/fred/Documents/Important/Passwords/Passwords.txt";

#[derive(Error)]
enum Error {
    #[error("Could not initialize logger, {0}")]
    LogInit(#[from] log::SetLoggerError),
    #[error("Could not read password file: {0}")]
    PassFile(io::Error),
    #[error("Could not parse entry, invalid marker {0}")]
    InvalidEntry(String),
    #[error("Could not run pwgen: {0}")]
    PwGenSpawn(io::Error),
    #[error("Could not wait on pwgen process: {0}")]
    PwGenWait(io::Error),
    #[error("Process pwgen failed with exit code {0}")]
    PwGenErr(i32),
    #[error("Process pwgen failed with exit code {0}: {1}")]
    PwGenErrMsg(i32, String),
    #[error("Process pwgen failed with exit code {0} but could not read its error message: {1}")]
    PwGenStderrErr(i32, io::Error),
    #[error("Process pwgen succeeded but did not generate anything")]
    PwGenNoStdout,
    #[error("Process pwgen succeeded but could not read its output: {0}")]
    PwGenStdoutErr(io::Error),
    #[error("Process pwgen died from a signal")]
    PwGenDied,
    #[error("Found {0} matches for {1}")]
    Mismatch(usize, String),
}

impl Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: {}", self)
    }
}

fn fmt_line(fmt: &str, acc: &[&str]) -> String {
    let mut iter = fmt.chars();
    let mut out = String::new();
    while let Some(c) = iter.next() {
        match c {
            '%' => match iter.next() {
                Some('N') => out.push_str(acc[1]),
                Some('L') => out.push_str(acc[2]),
                Some('U') => out.push_str(acc[3]),
                Some('P') => out.push_str(acc[4]),
                Some(c2) => {
                    out.push(c);
                    out.push(c2);
                }
                None => {
                    out.push(c);
                    break;
                }
            },
            _ => out.push(c),
        }
    }
    out
}

fn parse<'a>(data: &'a str) -> Vec<Vec<&str>> {
    let lines: Vec<Vec<&str>> = data
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        })
        .map(|line| line.split_whitespace().collect())
        .collect();
    debug!("{} password lines found", lines.len());
    lines
}

fn main() -> Result<(), Error> {
    let opt = Pw::from_args();

    let log_level = match opt.verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    env_logger::Builder::new()
        .filter_level(log_level)
        .try_init()?;

    match opt.command {
        Cmd::Check => {
            let data = fs::read_to_string(PASSFILE).map_err(Error::PassFile)?;
            let lines = parse(&data);
            let mut valid = 0;
            let mut invalid = 0;
            let mut change = 0;
            for line in lines {
                if line[0] == "+" {
                    valid += 1;
                } else if line[0] == "-" {
                    invalid += 1;
                } else if line[0] == "*" {
                    change += 1;
                } else {
                    return Err(Error::InvalidEntry(line[0].to_string()));
                }
            }
            println!(
                "{} current, {} inactive, {} need changing",
                valid, invalid, change
            );
        }
        Cmd::Generate => 'gen_loop: loop {
            let mut child = process::Command::new("pwgen")
                .args(&["-c", "-n", "-y", "-s", "-B", "-1", "34", "1"])
                .stdin(process::Stdio::null())
                .stdout(process::Stdio::piped())
                .stderr(process::Stdio::piped())
                .spawn()
                .map_err(Error::PwGenSpawn)?;

            let exit_status = child.wait().map_err(Error::PwGenWait)?;
            if !exit_status.success() {
                if let Some(code) = exit_status.code() {
                    if let Some(mut err) = child.stderr {
                        let mut err_str = String::new();

                        if let Err(e) = err.read_to_string(&mut err_str) {
                            return Err(Error::PwGenStderrErr(code, e));
                        } else {
                            let err_str = err_str.trim().to_string();
                            if err_str.is_empty() {
                                return Err(Error::PwGenErr(code));
                            } else {
                                return Err(Error::PwGenErrMsg(code, err_str));
                            }
                        }
                    } else {
                        return Err(Error::PwGenErr(code));
                    }
                } else {
                    return Err(Error::PwGenDied);
                }
            }

            if let Some(mut out) = child.stdout {
                let mut out_str = String::new();

                if let Err(e) = out.read_to_string(&mut out_str) {
                    return Err(Error::PwGenStdoutErr(e));
                } else {
                    let out_str = out_str.trim().to_string();

                    if let Some(c) = out_str.chars().next() {
                        if c.is_ascii_punctuation() {
                            info!("Password ({}) starts with a symbol", out_str);
                            continue 'gen_loop;
                        } else {
                            println!("{}", out_str);
                            break 'gen_loop;
                        }
                    } else {
                        return Err(Error::PwGenNoStdout);
                    }
                }
            } else {
                return Err(Error::PwGenNoStdout);
            }
        },
        Cmd::Get {
            account_name,
            format,
        } => {
            let data = fs::read_to_string(PASSFILE).map_err(Error::PassFile)?;
            let lines = parse(&data);
            let valid = lines.iter().filter(|line| line[0] == "+");
            let mut matched = valid.filter(|line| line[1] == account_name);
            let matches = matched.clone().count();
            if matches != 1 {
                return Err(Error::Mismatch(matches, account_name));
            }
            let acc = match matched.next() {
                Some(acc) => acc,
                _ => return Err(Error::Mismatch(matches, account_name)),
            };
            println!("{}", fmt_line(&format, acc));
        }
        Cmd::List { query } => {
            let data = fs::read_to_string(PASSFILE).map_err(Error::PassFile)?;
            let lines = parse(&data);
            let matched = lines.iter().filter(|line| {
                line[0] == "+" && line[1].to_lowercase().contains(&query.to_lowercase())
            });
            for acc in matched {
                println!("{}", fmt_line(&String::from("%N (%L) %U %P"), &acc));
            }
        }
    }

    Ok(())
}
