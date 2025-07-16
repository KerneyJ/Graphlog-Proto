use super::threadpool::ThreadPool;
use std::{
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
};

pub struct HttpServer {
    listener: TcpListener,
    pool: ThreadPool,
}

impl HttpServer {
    pub fn new(addr_port: String, num_threads: usize) -> HttpServer {
        let listener = match TcpListener::bind(&addr_port) {
            Err(why) => panic!("Error binding to {addr_port}: {why}"),
            Ok(listener) => listener,
        };
        HttpServer {
            listener,
            pool: ThreadPool::new(num_threads),
        }
    }

    pub fn run(&mut self) {
        for stream in self.listener.incoming() {
            let stream = stream.unwrap();

            self.pool.execute(|| {
                HttpServer::handle_connection(stream);
            });
        }
    }

    fn handle_connection(mut stream: TcpStream) {
        let mut buf_reader = BufReader::new(&stream);
        let mut request_header: Vec<String> = Vec::new();
        loop {
            let mut header_line = String::new();
            if let Err(why) = buf_reader.read_line(&mut header_line) {
                println!("Couldn't read line in http header: {why}");
                return;
            }

            if header_line == "\r\n" {
                break;
            }
            header_line = header_line.strip_suffix("\r\n").unwrap().to_string();
            request_header.push(header_line);
        }
        // println!("{request_header:?}") // For debug purposes
        let request_type: &String = request_header.first().unwrap();
        if *request_type == "POST / HTTP/1.1" {
            // println!("received post request"); // For debug purposes
            let content_size: usize = match request_header
                .iter()
                .find(|s| s.contains("Content-Length: "))
            {
                Some(found) => found
                    .strip_prefix("Content-Length: ")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap(),
                None => {
                    println!("Couldn't find content size in request header");
                    return;
                }
            };
            println!("content size: {content_size}");

            let mut content_raw = vec![0u8; content_size];
            if let Err(why) = buf_reader.read_exact(&mut content_raw) {
                println!("Error reading request buffer: {why}");
                return;
            }
            let content_str: String = match String::from_utf8(content_raw) {
                Err(why) => {
                    println!("Error parsing content string: {why}");
                    return;
                }
                Ok(string) => string,
            };
            println!("{content_str:?}");
        } else if request_type == "GET / HTTP/1.1" {
            println!("received a get request");
        } else {
            println!("No handler for request: {request_type:#?}");
        }

        let response = "HTTP/1.1 200 OK\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    }
}
