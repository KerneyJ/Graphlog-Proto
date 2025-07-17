use std::{
    io::{prelude::*, BufReader},
    net::TcpStream,
    sync::{Arc, Mutex},
};

use graphlog_proto::types::reid::Reid;
use graphlog_proto::utils::http_server::HttpServer;
use graphlog_proto::{
    types::{log::Log, reid},
    utils::http_server::ReidMessage,
};

use openssl::base64::decode_block;

fn main() {
    let addr_port = String::from("127.0.0.1:7878");
    let mut log = Arc::new(Mutex::new(Log::new()));
    let mut http_server = HttpServer::new(addr_port, 1, Arc::new(handle_connection));
    http_server.run(log);
}

fn handle_connection(mut stream: TcpStream, mut log: Arc<Mutex<Log<Reid>>>) {
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
    // println!("{request_header:#?}"); // For debug purposes
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
        let content_type: String =
            match request_header.iter().find(|s| s.contains("Content-Type: ")) {
                Some(found) => found.strip_prefix("Content-Type: ").unwrap().to_string(),
                None => {
                    println!("Couldn't find content-type in request header");
                    return;
                }
            };
        // println!("content size: {content_size}"); // DEBUG
        // println!("content type: {content_type}"); // DEBUG
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
        if content_type == "application/json" {
            let reid_json: ReidMessage = serde_json::from_str(&content_str).unwrap();
            let reid_b64: String = reid_json.reid;
            let reid_raw: String = String::from_utf8(decode_block(&reid_b64).unwrap()).unwrap();
            let reid: Reid = serde_json::from_str(&reid_raw).unwrap();
            log.lock().unwrap().append(reid);
            println!("Pushed reid to log");
        } else {
            println!("Recieved content_type: {content_type} that is not yet handled");
            return;
        }
        let response = "HTTP/1.1 200 OK\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    } else if request_type == "GET /tail HTTP/1.1" {
        println!("received a get request");
        let reid_b64: String = log.lock().unwrap().head().clone().encode();
        let response_body = format!("{{\"reid\": \"{reid_b64}\"}}");
        let response: String = format!(
            "HTTP/1.1 200 OK\r\n\nContent-Type: application/json\r\n\nContent-Length: {}\r\n\nConnection: close\r\n\n\r\n\n{}",
            response_body.len(),
            response_body,
        );
        stream.write_all(response.as_bytes()).unwrap();
    } else if request_type == "GET /head HTTP/1.1" {
        println!("received a get request");
        let reid_b64: String = log.lock().unwrap().tail().clone().encode();
        let response_body = format!("{{\"reid\": \"{reid_b64}\"}}");
        let response: String = format!(
            "HTTP/1.1 200 OK\r\n
             Content-Type: application/json\r\n
             Content-Length: {}\r\n
             Connection: close\r\n
             \r\n
             {}",
            response_body.len(),
            response_body,
        );
        stream.write_all(response.as_bytes()).unwrap();
    } else {
        println!("No handler for request: {request_type:#?}");
        let response = "HTTP/1.1 200 OK\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    }
}
