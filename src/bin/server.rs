use graphlog_proto::utils::threadpool::ThreadPool;
use std::io::{prelude::*, BufReader};
use std::net::{TcpListener, TcpStream};

fn main() {
    let listener = match TcpListener::bind("127.0.0.1:7878") {
        Err(why) => panic!("Error binding to 127.0.0.1:7878: {why}"),
        Ok(listener) => listener,
    };

    let pool = ThreadPool::new(4);

    for stream in listener.incoming() {
        let stream = stream.unwrap();

        pool.execute(|| {
            handle_connection(stream);
        });
    }
}

fn handle_connection(mut stream: TcpStream) {
    let mut buf_reader = BufReader::new(&stream);
    let mut request_header: Vec<String> = Vec::new();
    loop {
        let mut header_line = String::new();
        match buf_reader.read_line(&mut header_line) {
            Err(why) => panic!("Couldn't read line in http header: {why}"),
            Ok(n) => (), // n being the number of bytes read
        };

        if header_line == "\r\n" {
            break;
        }
        header_line = header_line.strip_suffix("\r\n").unwrap().to_string();
        request_header.push(header_line);
    }
    let request_type: &String = request_header.first().unwrap();
    if *request_type == "POST / HTTP/1.1" {
        println!("recieved a post request");
        let content_size: usize = request_header
            .get(5)
            .unwrap()
            .strip_prefix("Content-Length: ")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        println!("content size: {content_size}");

        let mut content_raw = vec![0u8; content_size];
        if let Err(why) = buf_reader.read_exact(&mut content_raw) {
            panic!("Error reading content of post request: {why}");
        }
        let content_str: String = match String::from_utf8(content_raw) {
            Err(why) => panic!("Error converting content into String: {why}"),
            Ok(string) => string,
        };
        println!("{content_str:?}");
    } else if request_type == "GET / HTTP/1.1" {
        println!("recieved a get request");
    } else {
        println!("No handler for request: {request_type:#?}");
    }

    let response = "HTTP/1.1 200 OK\r\n\r\n";
    stream.write_all(response.as_bytes()).unwrap();
}
