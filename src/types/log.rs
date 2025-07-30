use std::io::{BufRead, BufReader, Write};
use std::{fs::File, path::PathBuf};

use crate::types::common::Decodable;

use super::common::Encodable;

pub struct Log<T> {
    _log: Vec<T>,
    path: Option<PathBuf>,
    file_pos: usize,
    /* add other metadata below(merkel tree, head) */
}

impl<T> Log<T> {
    pub fn new(path: Option<String>) -> Log<T>
    where
        T: Encodable,
    {
        let _log: Vec<T> = Vec::new();
        Log {
            _log,
            path: path.map(PathBuf::from),
            file_pos: 0,
        }
    }

    pub fn new_from_file(path: String) -> Log<T>
    where
        T: Decodable<T>,
    {
        let file: File = match File::open(&path) {
            Err(why) => {
                println!("Couldn't open file: {why}");
                return Log {
                    _log: Vec::new(),
                    path: None,
                    file_pos: 0,
                };
            }
            Ok(file) => file,
        };
        let mut log: Vec<T> = Vec::new();
        let buf_reader = BufReader::new(file);

        for entry_b64 in buf_reader.lines() {
            if let Err(why) = entry_b64 {
                println!("Error reading line from file: {why}");
                continue;
            }
            let entry: T = match T::decode(&entry_b64.unwrap()) {
                Some(entry) => entry,
                None => panic!("Failed to read entry; log corrupted"),
            };
            log.push(entry);
        }

        let file_pos: usize = log.len();
        Log {
            _log: log,
            path: Some(PathBuf::from(&path)),
            file_pos,
        }
    }

    pub fn append(&mut self, val: T)
    where
        T: Encodable,
    {
        self._log.push(val);
        self.persist(); // TODO THIS IS TEMPORARY IN FUTURE PERSIST ON BATCH;
    }

    pub fn head(&mut self) -> Option<&T> {
        self._log.first()
    }

    pub fn tail(&self) -> Option<&T> {
        self._log.last()
    }

    pub fn tailn(&self, n: usize) -> Vec<T>
    where
        T: Clone,
    {
        let len: usize = self._log.len();
        let start = len.saturating_sub(n);
        self._log[start..].to_vec()
    }

    pub fn len(&self) -> usize {
        self._log.len()
    }

    pub fn is_empty(&self) -> bool {
        self._log.is_empty()
    }

    // Since the log is append only the item I want to find
    // is the most recent occurance so the list is reversed
    pub fn search<P>(&mut self, mut predicate: P) -> Option<&T>
    where
        P: FnMut(&T) -> bool,
    {
        self._log.iter().rev().find(|x| predicate(*x))
    }

    pub fn persist(&mut self)
    where
        T: Encodable,
    {
        if self.file_pos == self._log.len() {
            println!("No new records");
            return; // early return if we haven't had new entries
        }
        if let Some(path) = &self.path {
            let mut file: File = match File::options().append(true).create(true).open(path) {
                Err(why) => {
                    println!("Error opening file to persist log to: {why}");
                    return;
                }
                Ok(file) => file,
            };
            for idx in self.file_pos..self._log.len() {
                let entry: &T = self._log.get(idx).unwrap();
                let entry_b64 = entry.encode();
                writeln!(file, "{entry_b64}").unwrap(); // TODO should not just unwrap this
            }
            self.file_pos = self._log.len();
        } else {
            println!("No path configured to persist log to");
        }
    }
}
