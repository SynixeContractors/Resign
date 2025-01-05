use std::{collections::HashMap, path::Path, time::SystemTime};

use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct State {
    pub modified: HashMap<String, SystemTime>,
}

const STATE_FILE: &str = "pallas.toml";

impl State {
    /// Load the state from the given path
    ///
    /// # Errors
    /// If the file can't be read or the file is not valid toml
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let path = path.as_ref().join(STATE_FILE);
        let state = toml::from_str(&std::fs::read_to_string(&path)?)?;
        Ok(state)
    }

    /// Save the state to the given path
    ///
    /// # Errors
    /// If the file can't be written
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let path = path.as_ref().join(STATE_FILE);
        std::fs::write(&path, toml::to_string(self)?)?;
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
