//! Resource-limited sub-process execution (used for `git` and the optional test runner). No shell, empty environment, new process
//! group/session, wall-clock timeout, output cap enforced WHILE reading (the process is killed once exceeded).
//! Unix: setsid + RLIMIT_CPU/AS/FSIZE/CORE/NOFILE. Windows: Job Object (kill-on-close, per-process memory and CPU-time limits).
use crate::error::{Error, Result};
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct RunOpts<'a> {
    pub cwd: &'a Path,
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
    pub max_output: usize,
    pub cpu_s: u64,
    pub memory_mb: u64,
    /// RLIMIT_FSIZE (Unix); default `max_output + 1`.
    pub fsize: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct RunResult {
    pub returncode: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub truncated: bool,
}

#[cfg(windows)]
mod job {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::*;

    pub struct Job(HANDLE);
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    impl Job {
        pub fn new(memory_bytes: u64, cpu_seconds: u64) -> Option<Job> {
            unsafe {
                let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());

                if handle.is_null() {
                    return None;
                }

                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();

                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                    | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                    | JOB_OBJECT_LIMIT_PROCESS_TIME;

                info.BasicLimitInformation.PerProcessUserTimeLimit =
                    (cpu_seconds as i64).saturating_mul(10_000_000); // 100 ns units

                info.ProcessMemoryLimit = memory_bytes as usize;

                let ok = SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );

                if ok == 0 {
                    CloseHandle(handle);
                    return None;
                }
                Some(Job(handle))
            }
        }

        /// Small window between spawn and assignment: acceptable for short-lived git processes (documented in the README).
        pub fn assign(&self, child: &std::process::Child) -> bool {
            unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle() as HANDLE) != 0 }
        }

        pub fn terminate(&self) {
            unsafe {
                TerminateJobObject(self.0, 1);
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[allow(dead_code)]
enum Killer {
    #[cfg(unix)]
    Group(i32),
    #[cfg(windows)]
    Job(Arc<job::Job>),
    Plain,
}

impl Killer {
    fn kill(&self, child_id: u32) {
        match self {
            #[cfg(unix)]
            Killer::Group(pgid) => unsafe {
                libc::kill(-*pgid, libc::SIGKILL);
            },
            #[cfg(windows)]
            Killer::Job(job) => job.terminate(),
            Killer::Plain => {
                let _ = child_id;
            }
        }
    }
}

fn drain(
    mut reader: impl Read,
    cap: usize,
    kill_on_cap: Option<Arc<AtomicBool>>,
) -> (Vec<u8>, bool) {
    let (mut buf, mut chunk, mut exceeded) = (Vec::new(), [0u8; 16384], false);
    loop {
        match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buf.len() < cap + 1 {
                    let take = n.min(cap + 1 - buf.len());
                    buf.extend_from_slice(&chunk[..take]);
                }

                if buf.len() > cap && !exceeded {
                    exceeded = true;
                    if let Some(signal) = &kill_on_cap {
                        signal.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
    }
    (buf, exceeded)
}

pub fn run_limited(argv: &[String], run_opt: &RunOpts) -> Result<RunResult> {
    let prog = argv
        .first()
        .ok_or_else(|| Error::internal("ValueError", "argv is empty"))?;

    if !Path::new(prog).is_absolute() {
        return Err(Error::internal(
            "ValueError",
            "the executable should be an absolute file path",
        ));
    }

    let mut cmd = Command::new(prog);
    cmd.args(&argv[1..])
        .current_dir(run_opt.cwd)
        .env_clear()
        .envs(
            run_opt
                .env
                .iter()
                .map(|(key, val)| (key.as_str(), val.as_str())),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let (cpu, mem, fsize) = (
            run_opt.cpu_s,
            run_opt.memory_mb * 1024 * 1024,
            run_opt.fsize.unwrap_or(run_opt.max_output as u64 + 1),
        );
        // SAFETY: only async-signal-safe calls (setsid, setrlimit) between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                libc::setsid();
                let set = |res, val: u64| {
                    let limit = libc::rlimit {
                        rlim_cur: val as libc::rlim_t,
                        rlim_max: val as libc::rlim_t,
                    };
                    libc::setrlimit(res, &limit);
                };
                set(libc::RLIMIT_CPU, cpu);
                #[cfg(not(target_os = "macos"))]
                set(libc::RLIMIT_AS, mem);
                #[cfg(target_os = "macos")]
                let _ = mem;
                set(libc::RLIMIT_FSIZE, fsize);
                set(libc::RLIMIT_CORE, 0);
                set(libc::RLIMIT_NOFILE, 256);
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000 /* CREATE_NO_WINDOW */);
    }

    let mut child: Child = cmd
        .spawn()
        .map_err(|err| Error::internal("OSError", format!("failed to launch : {err}")))?;
    let pid = child.id();

    #[cfg(unix)]
    let killer = Killer::Group(pid as i32);
    #[cfg(windows)]
    let killer = match job::Job::new(run_opt.memory_mb * 1024 * 1024, run_opt.cpu_s) {
        Some(job) if job.assign(&child) => Killer::Job(Arc::new(job)),
        _ => Killer::Plain,
    };
    #[cfg(not(any(unix, windows)))]
    let killer = Killer::Plain;

    let kill_flag = Arc::new(AtomicBool::new(false));
    let (so, se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let (cap_out, cap_err) = (run_opt.max_output, run_opt.max_output.min(20_000));
    let kf = kill_flag.clone();
    let t_out = std::thread::spawn(move || drain(so, cap_out, Some(kf)));
    let t_err = std::thread::spawn(move || drain(se, cap_err, None));

    let (deadline, mut timed_out, mut delay) = (
        Instant::now() + run_opt.timeout,
        false,
        Duration::from_millis(1),
    );

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => break None,
        }

        if kill_flag.load(Ordering::SeqCst) || Instant::now() >= deadline {
            timed_out = !kill_flag.load(Ordering::SeqCst);
            killer.kill(pid);
            let _ = child.kill();
            break child.wait().ok();
        }

        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(20));
    };

    #[cfg(unix)]
    if timed_out || kill_flag.load(Ordering::SeqCst) {
        killer.kill(pid);
    }

    let (out, out_exceeded) = t_out.join().unwrap_or_default();
    let (err, _) = t_err.join().unwrap_or_default();

    let rc = status
        .map(|status| {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                status
                    .code()
                    .unwrap_or_else(|| -status.signal().unwrap_or(1))
            }
            #[cfg(not(unix))]
            {
                status.code().unwrap_or(-1)
            }
        })
        .unwrap_or(-1);

    let truncated = out_exceeded || (cfg!(unix) && rc == -25/* SIGXFSZ */);
    let cut = |bytes: Vec<u8>, cap: usize| {
        String::from_utf8_lossy(&bytes[..bytes.len().min(cap)]).into_owned()
    };

    Ok(RunResult {
        returncode: rc,
        stdout: cut(out, cap_out),
        stderr: cut(err, cap_err),
        timed_out,
        truncated,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    fn opts<'a>(cwd: &'a Path, t: u64, max: usize) -> RunOpts<'a> {
        RunOpts {
            cwd,
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            timeout: Duration::from_secs(t),
            max_output: max,
            cpu_s: 10,
            memory_mb: 2048,
            fsize: None,
        }
    }

    #[test]
    fn runs_with_minimal_env_and_caps() {
        let d = tempfile::tempdir().unwrap();
        let r = run_limited(&["/usr/bin/env".into()], &opts(d.path(), 5, 10_000)).unwrap();
        assert!(
            r.stdout.contains("PATH=") && !r.stdout.contains("HOME=/root") && r.returncode == 0
        );
        let r = run_limited(&["/usr/bin/yes".into()], &opts(d.path(), 5, 1000)).unwrap();
        assert!(
            r.truncated && r.stdout.len() <= 1000,
            "output cap enforced while reading"
        );
        let r = run_limited(
            &["/usr/bin/sleep".into(), "30".into()],
            &opts(d.path(), 1, 1000),
        )
        .unwrap();
        assert!(r.timed_out);
        assert!(
            run_limited(&["sleep".into()], &opts(d.path(), 1, 1000)).is_err(),
            "relative executable refused"
        );
    }
}
