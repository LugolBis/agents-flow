use std::fs::Metadata;

pub fn mode_string(meta_data: &Metadata) -> String {
    let typ = if meta_data.file_type().is_symlink() {
        'l'
    } else if meta_data.is_dir() {
        'd'
    } else {
        '-'
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bits = meta_data.permissions().mode();
        let mut res = String::from(typ);
        for (index, char_) in "rwxrwxrwx".chars().enumerate() {
            res.push(if bits & (1 << (8 - index)) != 0 {
                char_
            } else {
                '-'
            });
        }
        res
    }
    #[cfg(not(unix))]
    {
        format!(
            "{typ}{}",
            if meta_data.permissions().readonly() {
                "r-xr-xr-x"
            } else {
                "rwxrwxrwx"
            }
        )
    }
}

pub fn octal_mode(meta_data: &Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta_data.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        if meta_data.permissions().readonly() {
            0o444
        } else {
            0o666
        }
    }
}

pub fn ids(meta_data: &Metadata) -> (u64, u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            meta_data.uid() as u64,
            meta_data.gid() as u64,
            meta_data.nlink(),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = meta_data;
        (0, 0, 1)
    }
}
