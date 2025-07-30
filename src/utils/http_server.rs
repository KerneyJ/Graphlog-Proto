use super::threadpool::ThreadPool;
use crate::types::log::Log;
use crate::types::reid::Reid;
use serde::Deserialize;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

#[derive(Deserialize, Debug)]
pub struct ReidMessage {
    pub reid: Reid,
    pub pub_key: String,
}

#[derive(Deserialize, Debug)]
pub struct IdMessage {
    pub id_b64: String,
}

pub struct HttpServer {
    listener: TcpListener,
    pool: ThreadPool,
    handler: Arc<dyn Fn(TcpStream, Arc<Mutex<Log<Reid>>>) + Send + Sync + 'static>,
}

impl HttpServer {
    pub fn new(
        addr_port: String,
        num_threads: usize,
        handler: Arc<dyn Fn(TcpStream, Arc<Mutex<Log<Reid>>>) + Send + Sync + 'static>,
    ) -> HttpServer {
        let listener = match TcpListener::bind(&addr_port) {
            Err(why) => panic!("Error binding to {addr_port}: {why}"),
            Ok(listener) => listener,
        };
        HttpServer {
            listener,
            pool: ThreadPool::new(num_threads),
            handler,
        }
    }

    pub fn run(&mut self, log: Arc<Mutex<Log<Reid>>>) {
        for stream in self.listener.incoming() {
            let stream = stream.unwrap();
            let handler = Arc::clone(&self.handler);
            let log = Arc::clone(&log);
            self.pool.execute(move || {
                handler(stream, log);
            });
        }
    }
}
