use std::{collections::HashMap, path::Path, time::SystemTime};

use savefile_derive::Savefile;

#[derive(Default, Debug, Savefile)]
pub struct State {
    pub modified: HashMap<String, SystemTime>,
}

const STATE_FILE: &str = "pallas.state";
const VERSION: u32 = 0;

impl State {
    /// Load the state from the given path
    ///
    /// # Errors
    /// If the file can't be read
    /// 
    /// # Panics
    /// If the path can't be converted to a string
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let path = path.as_ref().join(STATE_FILE);
        let state = savefile::load_file(path.to_str().expect("path can be str"), VERSION)?;
        Ok(state)
    }

    /// Save the state to the given path
    ///
    /// # Errors
    /// If the file can't be written
    ///
    /// # Panics
    /// If the path can't be converted to a string
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let path = path.as_ref().join(STATE_FILE);
        savefile::save_file(path.to_str().expect("path can be str"), VERSION, self)?;
        Ok(())
    }

    #[must_use]
    pub fn modified(&self, name: &str) -> Option<SystemTime> {
        self.modified.get(name).copied()
    }

    pub fn update(&mut self, name: String, modified: SystemTime) {
        self.modified.insert(name, modified);
    }
}
