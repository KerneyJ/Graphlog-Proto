pub struct Log<T> {
    _log: Vec<T>,
    /* add other metadata below(merkel tree, head) */
}

impl<T> Log<T> {
    pub fn new() -> Log<T> {
        let _log: Vec<T> = Vec::new();
        Log { _log }
    }

    pub fn append(&mut self, val: T) {
        self._log.push(val);
    }

    pub fn head(&mut self) -> &T {
        self._log.first().unwrap()
    }

    pub fn tail(&mut self) -> &T {
        self._log.last().unwrap()
    }
}
