//! WSL launcher and installer. The WSL command line never goes through a Linux shell: either `wsl --shell-type none -- cmd args` or
//! `wsl --exec cmd args` is used, and every configured value was restricted to safe characters at load time.
use crate::config::{models::deployment::WslCfg, Settings};
use crate::error::{Error, Result};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

pub struct Wsl {
    pub cfg: WslCfg,
}

impl Wsl {
    pub fn new(settings: &Settings) -> Wsl {
        Wsl {
            cfg: settings.deployment.wsl.clone(),
        }
    }

    pub fn prefix(&self) -> Vec<String> {
        let mut vec = vec![self.cfg.exe.clone(), "-d".into(), self.cfg.distro.clone()];

        if let Some(user) = &self.cfg.user {
            vec.extend(["-u".into(), user.clone()]);
        }

        if self.cfg.launch == "exec" {
            vec.push("--exec".into());
        } else {
            vec.extend(["--shell-type".into(), "none".into(), "--".into()]);
        }

        vec
    }

    pub fn run_once(&self, cmd: &[&str], stdin: Option<&[u8]>) -> Result<(i32, String, String)> {
        let prefixes = self.prefix();
        let mut command = Command::new(&prefixes[0]);

        command
            .args(&prefixes[1..])
            .args(cmd)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|err| Error::internal("OSError", format!("wsl not found ({err})")))?;

        if let (Some(data), Some(mut si)) = (stdin, child.stdin.take()) {
            si.write_all(data)?;
        }

        let out = child.wait_with_output()?;
        Ok((
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }

    pub fn home(&self) -> Result<String> {
        let (code, out, _) = self.run_once(&["/usr/bin/printenv", "HOME"], None)?;

        if code != 0 || out.trim().is_empty() {
            return Err(Error::internal(
                "WslError",
                "HOME not found in the distribution",
            ));
        }

        Ok(out.trim().to_string())
    }

    pub fn expand(&self, path: &str) -> Result<String> {
        Ok(if path == "~" || path.starts_with("~/") {
            format!("{}{}", self.home()?, &path[1..])
        } else {
            path.to_string()
        })
    }

    /// `wsl.exe -l -q` prints UTF-16LE.
    pub fn list_distros(&self) -> Vec<String> {
        let Ok(output) = Command::new(&self.cfg.exe).args(["-l", "-q"]).output() else {
            return vec![];
        };

        let u16s: Vec<u16> = output
            .stdout
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .collect();

        String::from_utf16_lossy(&u16s)
            .lines()
            .map(|line| {
                line.trim()
                    .trim_matches('\u{feff}')
                    .trim_matches('\0')
                    .to_string()
            })
            .filter(|line| !line.is_empty())
            .collect()
    }

    pub fn executor_argv(&self) -> Result<Vec<String>> {
        let inst = self.expand(&self.cfg.install_dir)?;
        let env = self.expand(&self.cfg.env_file)?;
        let mut prefixes = self.prefix();

        prefixes.extend([
            format!("{inst}/agwo"),
            "executor".into(),
            "--serve".into(),
            "--config".into(),
            format!("{inst}/config"),
            "--env-file".into(),
            env,
            "--max-bytes".into(),
            self.cfg.max_message_bytes.to_string(),
        ]);

        Ok(prefixes)
    }

    /// ELF `e_machine` -> architecture name.
    pub fn elf_arch(bin: &[u8]) -> Option<&'static str> {
        if bin.len() < 20 || &bin[..4] != b"\x7fELF" {
            return None;
        }

        match u16::from_le_bytes([bin[18], bin[19]]) {
            0xB7 => Some("aarch64"),
            0x3E => Some("x86_64"),
            _ => None,
        }
    }

    /// Copies config + skills + the LINUX build of this program into the distribution (tar over stdin; no mounted drive involved).
    pub fn sync(&self, settings: &Settings, linux_binary: &Path) -> Result<String> {
        let bin = std::fs::read(linux_binary)?;
        let arch = Self::elf_arch(&bin).ok_or_else(|| {
            Error::config("--binary should be an executable Linux ELF (aarch64 ou x86_64)")
        })?;

        let (_, un, _) = self.run_once(&["/usr/bin/uname", "-m"], None)?;
        let distro_arch = un.trim().to_string();

        if distro_arch != arch {
            return Err(Error::config(format!("incompatible architecture: binary {arch}, WSL distribution {distro_arch} (compile for {distro_arch}-unknown-linux-gnu)")));
        }

        let inst = self.expand(&self.cfg.install_dir)?;
        let mut tar = tar::Builder::new(Vec::new());

        let mut add = |name: &str, data: &[u8], mode: u32| -> Result<()> {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(mode);
            header.set_cksum();
            tar.append_data(&mut header, name, data)
                .map_err(Error::from)
        };

        add("agwo", &bin, 0o755)?;
        for n in ["agents.jsonc", "permissions.jsonc", "tools.jsonc"] {
            let text = fs::read_to_string(settings.config_dir.join(n))?.replace("\r\n", "\n");
            add(&format!("config/{n}"), text.as_bytes(), 0o644)?;
        }

        let schema_dir = fs::read_dir(settings.config_dir.join("schemas")).map_err(|err| {
            Error::config(format!(
                "Failed to read '{:?}' entries due to {}.",
                settings.config_dir.join("schemas"),
                err
            ))
        })?;

        for entry_res in schema_dir {
            match &entry_res {
                Ok(entry) => {
                    let path_ = settings.config_dir.join("schemas").join(entry.file_name());
                    let text = fs::read_to_string(&path_)?.replace("\r\n", "\n");
                    add(
                        &format!(
                            "config/schemas/{}",
                            path_
                                .file_name()
                                .and_then(|s| s.to_str())
                                .ok_or(Error::Config(format!(
                                    "Failed to get the file name of the path {:?}",
                                    path_
                                )))?
                        ),
                        text.as_bytes(),
                        0o644,
                    )?;
                }
                Err(err) => {
                    return Err(Error::config(format!(
                        "Failed to read '{:?}' entry due to {}.",
                        entry_res, err
                    )))
                }
            }
        }

        if let Some(sk) = settings
            .config_dir
            .parent()
            .map(|path| path.join("skills"))
            .filter(|path| path.is_dir())
        {
            fn walk(
                base: &Path,
                dir: &Path,
                add: &mut dyn FnMut(&str, &[u8], u32) -> Result<()>,
            ) -> Result<()> {
                for entry in fs::read_dir(dir)?.flatten() {
                    let path = entry.path();

                    if path.is_dir() {
                        walk(base, &path, add)?;
                    } else if let Ok(rel) = path.strip_prefix(base.parent().unwrap_or(base)) {
                        add(
                            &rel.to_string_lossy().replace('\\', "/"),
                            &fs::read(&path)?,
                            0o644,
                        )?;
                    }
                }
                Ok(())
            }
            walk(&sk, &sk, &mut add)?;
        }

        let data = tar.into_inner().map_err(Error::from)?;
        for step in [
            vec!["/usr/bin/mkdir", "-p", inst.as_str()],
            vec![
                "/usr/bin/rm",
                "-rf",
                &format!("{inst}/config"),
                &format!("{inst}/skills"),
            ],
        ] {
            let (rc, _, e) = self.run_once(&step, None)?;
            if rc != 0 {
                return Err(Error::internal("WslError", e.trim().to_string()));
            }
        }

        let (code, _, err) =
            self.run_once(&["/usr/bin/tar", "-xf", "-", "-C", &inst], Some(&data))?;
        if code != 0 {
            return Err(Error::internal("WslError", err.trim().to_string()));
        }

        Ok(format!(
            "synchronized in {inst} ({} octets, {arch})",
            data.len()
        ))
    }
}
