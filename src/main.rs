#![warn(clippy::all)]

use log::info;
use std::fmt::{self, Debug};
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::path::PathBuf;
use std::process;
use structopt::StructOpt;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, StructOpt)]
enum Cmd {
    #[structopt(about = "Check and print password stats")]
    Check {
        #[structopt(help = "Password file")]
        file: Option<PathBuf>,
    },
    #[structopt(name = "gen", about = "Generate a password")]
    Generate,
    #[structopt(about = "Retrieve a password")]
    Get {
        #[structopt(name = "account name", help = "Exact match for an account name")]
        acc: String,
        #[structopt(help = "Format: %N = Name, %L = Link, %U = Username, %P = Password")]
        format: String,
        #[structopt(help = "Password file")]
        file: Option<PathBuf>,
    },
    #[structopt(name = "ls", about = "Search for passwords")]
    List {
        #[structopt(help = "Query for an account name")]
        query: String,
        #[structopt(help = "Password file")]
        file: Option<PathBuf>,
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

#[derive(Error)]
enum Error {
    #[error("Could not initialize logger, {0}")]
    LogInit(#[from] log::SetLoggerError),
    #[error("Could not read password file: {0}")]
    PassFile(io::Error),
    #[error("Invalid entry at line {0}, missing marker")]
    MissingMarker(usize),
    #[error("Invalid entry at line {0}, missing name")]
    MissingName(usize),
    #[error("Invalid entry at line {0}, missing link")]
    MissingLink(usize),
    #[error("Invalid entry at line {0}, missing username")]
    MissingUsername(usize),
    #[error("Invalid entry at line {0}, missing password")]
    MissingPassword(usize),
    #[error("Invalid entry at line {0}, invalid marker {0}")]
    InvalidEntryMarker(usize, String),
    #[error("Could not run pwgen: {0}")]
    PwGenSpawn(io::Error),
    #[error("Could not wait on pwgen process: {0}")]
    PwGenWait(io::Error),
    #[error("Pwgen failed with exit code {0}")]
    PwGenErr(i32),
    #[error("Pwgen failed (exit code {0}): {1}")]
    PwGenErrMsg(i32, String),
    #[error("Pwgen failed (exit code {0}) but could not read its error message: {1}")]
    PwGenStderrErr(i32, io::Error),
    #[error("Pwgen succeeded but did not generate anything")]
    PwGenNoStdout,
    #[error("Pwgen succeeded but could not read its output: {0}")]
    PwGenStdoutErr(io::Error),
    #[error("Pwgen died from a signal")]
    PwGenDied,
    #[error("Found more than 1 match for {0}")]
    Mismatch(String),
    #[error("No matches found for {0}")]
    NoMatches(String),
    #[error("No default password file found in HOME/.passfile")]
    NoPassFile,
}

impl Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

fn fmt_entry(fmt: &str, entry: EntryData) -> String {
    let mut iter = fmt.chars();
    let mut out = String::new();
    while let Some(c) = iter.next() {
        match c {
            '%' => match iter.next() {
                Some('N') => out.push_str(entry.name),
                Some('L') => out.push_str(entry.link),
                Some('U') => out.push_str(entry.username),
                Some('P') => out.push_str(entry.password),
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

#[derive(Debug)]
struct EntryData<'a> {
    name: &'a str,
    link: &'a str,
    username: &'a str,
    password: &'a str,
}

impl<'a> EntryData<'a> {
    fn parse(num: usize, mut iter: impl Iterator<Item = &'a str>) -> Result<Self, Error> {
        Ok(EntryData {
            name: iter.next().ok_or_else(|| Error::MissingName(num))?,
            link: iter.next().ok_or_else(|| Error::MissingLink(num))?,
            username: iter.next().ok_or_else(|| Error::MissingUsername(num))?,
            password: iter.next().ok_or_else(|| Error::MissingPassword(num))?,
        })
    }
}

enum Entry<'a> {
    Valid(EntryData<'a>),
    Invalid(EntryData<'a>),
    Change(EntryData<'a>),
}

impl<'a> Entry<'a> {
    fn parse(num: usize, mut iter: impl Iterator<Item = &'a str>) -> Result<Self, Error> {
        let marker = iter.next().ok_or_else(|| Error::MissingMarker(num))?;
        let data = EntryData::parse(num, iter)?;
        match marker {
            "+" => Ok(Entry::Valid(data)),
            "-" => Ok(Entry::Invalid(data)),
            "*" => Ok(Entry::Change(data)),
            _ => Err(Error::InvalidEntryMarker(num, marker.to_string())),
        }
    }
}

fn parse(data: &str) -> impl Iterator<Item = Result<Entry, Error>> {
    data.lines()
        .enumerate()
        .filter(|(_, line)| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        })
        .map(|(num, line)| Entry::parse(num + 1, line.split_whitespace()))
}

fn read<P: AsRef<Path>>(file: P) -> Result<String, Error> {
    fs::read_to_string(file).map_err(Error::PassFile)
}

fn check(file: PathBuf) -> Result<(), Error> {
    let mut data = read(file)?;
    let entries = parse(&data);
    let mut valid = 0;
    let mut invalid = 0;
    let mut change = 0;
    for entry in entries {
        let entry = entry?;
        match entry {
            Entry::Valid(_) => valid += 1,
            Entry::Invalid(_) => invalid += 1,
            Entry::Change(_) => change += 1,
        }
    }
    data.zeroize();

    println!(
        "{} current, {} inactive, {} need changing",
        valid, invalid, change
    );

    Ok(())
}

fn generate() -> Result<(), Error> {
    'gen_loop: loop {
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
    }

    Ok(())
}

fn get(file: PathBuf, acc: String, format: String) -> Result<(), Error> {
    let mut data = read(file)?;
    let entries = parse(&data);
    let mut matched = None;
    for entry in entries {
        if let Entry::Valid(data) = entry? {
            if data.name == acc {
                if matched.is_some() {
                    return Err(Error::Mismatch(acc));
                }
                matched = Some(data);
            }
        }
    }
    if let Some(entry) = matched {
        println!("{}", fmt_entry(&format, entry));
    } else {
        return Err(Error::NoMatches(acc));
    }
    data.zeroize();
    Ok(())
}

fn list(file: PathBuf, query: String) -> Result<(), Error> {
    let mut data = read(file)?;
    let entries = parse(&data);
    for entry in entries {
        if let Entry::Valid(data) = entry? {
            if data.name.to_lowercase().contains(&query.to_lowercase()) {
                println!("{}", fmt_entry(&String::from("%N (%L) %U %P"), data));
            }
        }
    }
    data.zeroize();
    Ok(())
}

fn default_passfile() -> Option<PathBuf> {
    let mut passfile = dirs::home_dir()?;

    passfile.push(".passfile");

    if passfile.is_file() {
        return Some(passfile);
    }

    None
}

fn get_passfile(file: Option<PathBuf>) -> Result<PathBuf, Error> {
    let file = file.or_else(default_passfile);

    if let Some(file) = file {
        info!("Found password file at {}", file.display());
        Ok(file)
    } else {
        Err(Error::NoPassFile)
    }
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
        Cmd::Check { file } => check(get_passfile(file)?),
        Cmd::Generate => generate(),
        Cmd::Get { file, acc, format } => get(get_passfile(file)?, acc, format),
        Cmd::List { file, query } => list(get_passfile(file)?, query),
    }
}
