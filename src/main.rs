use std::{
    fs::File,
    sync::Arc,
    time::{Duration, SystemTime},
};

use dashmap::DashMap;
use hemtt_pbo::ReadablePbo;
use hemtt_signing::BIPrivateKey;
use indicatif::ProgressBar;
use pallas::state::State;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

#[allow(clippy::too_many_lines)]
fn main() {
    // first cli arg is the source directory
    let src_dir = std::env::args()
        .nth(1)
        .expect("Please provide the source directory");

    // check for -v or other - flags
    if src_dir.starts_with('-') {
        if src_dir == "-v" {
            println!("v{}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        println!("Unknown flag: {src_dir}");
        std::process::exit(1);
    }

    // Any other arguments are added to the forced list
    let forced = std::env::args().skip(2).collect::<Vec<String>>();

    let src_dir = std::path::Path::new(&src_dir);
    if !src_dir.exists() || !src_dir.is_dir() {
        println!("Source directory does not exist");
        std::process::exit(1);
    }

    let previous_state = State::load(src_dir).unwrap_or_default();
    let mut new_state = State::default();

    let keys = DashMap::new();

    let mut mods = Vec::new();
    let mut addons = Vec::new();
    for dirs in std::fs::read_dir(src_dir).expect("can't read root dir") {
        let dir = dirs.expect("can't read dir");
        if !dir.path().is_dir() {
            continue;
        }
        if !dir
            .file_name()
            .to_str()
            .expect("can't convert dir name to string")
            .starts_with('@')
        {
            continue;
        }

        if !dir.path().join("addons").exists() {
            println!("No addons folder in {}", dir.path().display());
            continue;
        }

        let mut saw_ebo = false;
        let mut saw_pbo = false;
        let mut maybe_addons = Vec::new();
        let mut modified = SystemTime::UNIX_EPOCH;
        for addon in std::fs::read_dir(dir.path().join("addons")).expect("can't read addons dir") {
            let addon = addon.expect("can't read addon");
            match addon
                .path()
                .extension()
                .expect("can't get extension")
                .to_str()
                .expect("can't convert ext to str")
            {
                "pbo" => {
                    maybe_addons.push(addon.path());
                    let meta = addon.metadata().expect("can't read metadata");
                    if meta.modified().expect("can't read modified") > modified {
                        modified = meta.modified().expect("can't read modified");
                    }
                    saw_pbo = true;
                }
                "ebo" => {
                    saw_ebo = true;
                }
                _ => {}
            }
        }
        if !saw_pbo {
            continue;
        }
        mods.push((dir.path(), saw_ebo));

        let dir_name = dir
            .file_name()
            .to_str()
            .expect("can't convert dir name to string")
            .to_string();

        if !forced.contains(&dir_name) {
            if let Some(last_modified) = previous_state.modified(&dir_name) {
                if last_modified >= modified {
                    new_state.update(dir_name.to_string(), modified);
                    continue;
                }
            }
        }
        println!("Generating key for {dir_name}");
        new_state.update(
            dir_name.to_string(),
            SystemTime::now() - Duration::from_secs(1),
        );

        keys.insert(
            dir_name.to_string(),
            BIPrivateKey::generate(
                2048,
                &format!(
                    "pallas_{}",
                    dir.file_name()
                        .to_str()
                        .expect("can't convert dir name to string")
                ),
            )
            .expect("can't generate private key"),
        );

        for addon in std::fs::read_dir(dir.path().join("addons")).expect("can't read addons dir") {
            let addon = addon.expect("can't read addon");
            if addon.path().extension() == Some(std::ffi::OsStr::new("bisign"))
                && !addon
                    .path()
                    .to_str()
                    .expect("can't convert path to str")
                    .contains(".ebo.")
            {
                std::fs::remove_file(addon.path()).expect("can't remove bisgn");
            }
        }
        addons.extend(maybe_addons);
    }
    println!("Signing {} addons", addons.len());
    if addons.len() < 30 && !addons.is_empty() {
        println!("Addons: {addons:?}");
    }

    let pb = ProgressBar::new(addons.len() as u64);
    let keys = Arc::new(keys);
    addons.par_iter().for_each(|addon| {
        let keys = keys.clone();
        let authority = addon
            .parent()
            .expect("can't get first parent")
            .parent()
            .expect("can't get second parent")
            .file_name()
            .expect("can't get file name");
        let private = keys
            .get(
                authority
                    .to_str()
                    .expect("can't convert dir name to string"),
            )
            .expect("can't get private key")
            .clone();
        let result = std::panic::catch_unwind(|| {
            let sig = private
                .sign(
                    &mut ReadablePbo::from(File::open(addon).expect("can't open pbo"))
                        .expect("can't read pbo"),
                    hemtt_pbo::BISignVersion::V3,
                )
                .expect("can't sign pbo");
            let addon_sig = addon.with_extension(format!(
                "pbo.pallas_{}.bisign",
                authority
                    .to_str()
                    .expect("can't convert dir name to string")
                    .trim_start_matches('@')
            ));
            sig.write(&mut File::create(addon_sig).expect("can't create bisign"))
                .expect("can't write bisign");
        });
        if result.is_err() {
            println!("Failed to sign {}", addon.display());
            eprintln!("{result:?}");
        }
        pb.inc(1);
    });

    for (mod_folder, saw_ebo) in mods {
        let Some(private) = keys.get(
            mod_folder
                .file_name()
                .expect("can't get file name")
                .to_str()
                .expect("can't convert dir name to string"),
        ) else {
            continue;
        };
        if !saw_ebo {
            for key_dir in ["key", "keys"] {
                let key_dir = mod_folder.join(key_dir);
                if key_dir.exists() {
                    std::fs::remove_dir_all(key_dir).expect("can't remove key dir");
                }
            }
        }
        std::fs::create_dir(mod_folder.join("keys")).expect("can't create keys dir");
        private
            .to_public_key()
            .write(
                &mut File::create(mod_folder.join("keys").join(format!(
                        "pallas_{}.bikey",
                        mod_folder
                            .file_name()
                            .expect("can't get file name")
                            .to_str()
                            .expect("can't convert dir name to string")
                            .trim_start_matches('@')
                    )))
                .expect("can't create bikey"),
            )
            .expect("can't write bikey");
    }
    pb.finish_with_message("Done, created private keys and signed addons");
    new_state.save(src_dir).expect("can't save state");
}
