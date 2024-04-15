use std::{fs::File, time::SystemTime};

use hemtt_pbo::ReadablePbo;
use hemtt_signing::BIPrivateKey;
use indicatif::ProgressBar;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

fn main() {
    let keys_dir = std::path::Path::new("pkeys");
    if !keys_dir.exists() {
        std::fs::create_dir(keys_dir).expect("can't create keys dir");
    }
    let mut mods = Vec::new();
    let mut addons = Vec::new();
    for dirs in std::fs::read_dir("src").expect("can't read root dir") {
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
        for key_dir in ["key", "keys"] {
            let keys = dir.path().join(key_dir);
            if keys.exists() {
                std::fs::remove_dir_all(keys).expect("can't remove keys dir");
            }
        }
        let mut maybe_addons = Vec::new();
        let mut modified = SystemTime::UNIX_EPOCH;
        for addon in std::fs::read_dir(dir.path().join("addons")).expect("can't read addons dir") {
            let addon = addon.expect("can't read addon");
            if addon.path().extension() == Some(std::ffi::OsStr::new("pbo")) {
                maybe_addons.push(addon.path());
                let meta = addon.metadata().expect("can't read metadata");
                if meta.modified().expect("can't read modified") > modified {
                    modified = meta.modified().expect("can't read modified");
                }
            }
        }
        let private_key_path = keys_dir
            .join(dir.file_name())
            .with_extension("biprivatekey");
        mods.push(dir.path());
        if private_key_path.exists() {
            let existing_key_meta = private_key_path.metadata().expect("can't read metadata");
            if existing_key_meta.modified().expect("can't read modified") >= modified {
                continue;
            }
            println!(
                "Outdated key for {}, key {} vs addons {}",
                dir.file_name()
                    .to_str()
                    .expect("can't convert dir name to string"),
                existing_key_meta
                    .modified()
                    .expect("can't read modified")
                    .elapsed()
                    .expect("can't read elapsed")
                    .as_secs(),
                modified.elapsed().expect("can't read elapsed").as_secs()
            );
        }
        let private = BIPrivateKey::generate(
            2048,
            &format!(
                "resign_{}",
                dir.file_name()
                    .to_str()
                    .expect("can't convert dir name to string")
            ),
        )
        .expect("can't generate private key");
        private
            .write_danger(&mut File::create(private_key_path).expect("can't create bikey"))
            .expect("can't write bikey");
        for addon in std::fs::read_dir(dir.path().join("addons")).expect("can't read addons dir") {
            let addon = addon.expect("can't read addon");
            if addon.path().extension() == Some(std::ffi::OsStr::new("bisign")) {
                std::fs::remove_file(addon.path()).expect("can't remove bisgn");
            }
        }
        addons.extend(maybe_addons);
    }
    println!("Signing {} addons", addons.len());
    if addons.len() < 30 {
        println!("Addons: {:?}", addons);
    }

    let pb = ProgressBar::new(addons.len() as u64);
    addons.par_iter().for_each(|addon| {
        let result = std::panic::catch_unwind(|| {
            let authority = addon
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .file_name()
                .unwrap();
            let private_key_path = keys_dir.join(authority).with_extension("biprivatekey");
            let private = BIPrivateKey::read(
                &mut File::open(private_key_path).expect("can't open private key"),
            )
            .expect("can't read private key");
            let sig = private
                .sign(
                    &mut ReadablePbo::from(File::open(addon).expect("can't open pbo"))
                        .expect("can't read pbo"),
                    hemtt_pbo::BISignVersion::V3,
                )
                .expect("can't sign pbo");
            let addon_sig = addon.with_extension(format!(
                "resign_{}.bisign",
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
            eprintln!("{:?}", result);
        }
        pb.inc(1);
    });

    for mod_folder in mods {
        std::fs::create_dir(mod_folder.join("keys")).expect("can't create keys dir");
        let private_key_path = keys_dir
            .join(mod_folder.file_name().unwrap())
            .with_extension("biprivatekey");
        let private =
            BIPrivateKey::read(&mut File::open(private_key_path).expect("can't open private key"))
                .expect("can't read private key");
        private
            .to_public_key()
            .write(
                &mut File::create(mod_folder.join("keys").join(format!(
                        "resign_{}.bikey",
                        mod_folder
                            .file_name()
                            .unwrap()
                            .to_str()
                            .expect("can't convert dir name to string")
                            .trim_start_matches('@')
                    )))
                .expect("can't create bikey"),
            )
            .expect("can't write bikey");
    }

    pb.finish_with_message("Done, created synixe_resign.bikey");
}
