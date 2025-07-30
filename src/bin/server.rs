use std::{
    io::{prelude::*},
    sync::{Arc, Mutex},
};

use dialoguer::Input;

use graphlog_proto::{
    types::{
        common::{id_equal, Encodable, Id},
        reid::Reid,
        log::Log
    },
    utils::http_server::{
        IdMessage,
        ReidMessage,
    },
};

use openssl::{
    base64::decode_block,
    pkey::{PKey, Public},
};

use axum::{
    extract::{Path, State, Json},
    routing::{get, post},
    http::StatusCode,
    serve,
    Router,
};

use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let addr_port: String = Input::new()
        .with_prompt("Enter IP address to bind to")
        .default(String::from("127.0.0.1:7878"))
        .interact_text()
        .unwrap();
    let persist_file: Option<String> = Input::new()
        .with_prompt("Enter the compelte file path to persist the log")
        .allow_empty(true)
        .interact_text()
        .ok()
        .filter(|s: &String| !s.trim().is_empty());

    // TODO make this cleaner, I know there is a much better way
    // organize this code, probably change log.rs too
    let mut log: Arc<Mutex<Log<Reid>>>;
    if let Some(path) = persist_file {
        log = Arc::new(Mutex::new(Log::new_from_file(path)));
    } else {
        log = Arc::new(Mutex::new(Log::new(persist_file)));
    }

    // Endpoints
    // /publish => post request, server receives a base64 encode reid
    // /tail => get request, server sends the reid at the end of the log
    // /tail_{num} => get request, retrieves most recent and num-1 reids before it
    //             => speical case for tail_all try to get all the log
    //             => will need some way to quantify stailness to tell the client
    // /{id} => get request, server attempts to look up reid at
    let app = Router::new()
        .route("/publish", post(publish)).with_state(log)
        .route("/tail", get(tail))
        .route("/tail_{num}", get(tail_num))
        .route("/{id}", get(lookup)).with_state(log);

    let listener = TcpListener::bind(addr_port)
        .await
        .unwrap();
    serve(listener, app).await.unwrap();
}

async fn publish(
    State(log): State<Arc<Mutex<Log<Reid>>>>,
    Json(reid_msg): Json<ReidMessage>,
) {
    let reid: Reid = reid_msg.reid;
    let pubk_str: String = reid_msg.pub_key;
    let pubk: PKey<Public> = PKey::public_key_from_pem(pubk_str.as_bytes()).unwrap();
    if reid.verify_sig(&pubk) {
        log.lock().unwrap().append(reid);
        println!("Pushed reid to log");
    }
    else {
        println!("Could not verify signature");
    }
}


async fn tail(State(log): State<Arc<Mutex<Log<Reid>>>>) -> Reid {
    log.lock().unwrap().tail().clone()
}

async fn tail_num(Path(num): Path<String>, State(log): State<Arc<Mutex<Log<Reid>>>>) -> Vec<Reid> {
    if num == "all" {
        panic!("Send entire log not implemented");
    }
   log.lock().unwrap().tailn(num.parse().expect("Couldn't convert to usize"))
}

async fn lookup(
    Path(id): Path<String>,
    State(log): State<Arc<Mutex<Log<Reid>>>>,
) -> String {
    let content_size: usize = match request.iter().find(|s| s.contains("Content-Length: ")) {
        Some(found) => found
            .strip_prefix("Content-Length: ")
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        None => {
            println!("Couldn't find content size in request header");
            return None;
        }
    };
    let content_type: String = match request.iter().find(|s| s.contains("Content-Type: ")) {
        Some(found) => found.strip_prefix("Content-Type: ").unwrap().to_string(),
        None => {
            println!("Couldn't find content-type in request header");
            return None;
        }
    };
    let mut content_raw = vec![0u8; content_size];
    if let Err(why) = buf_reader.read_exact(&mut content_raw) {
        println!("Error reading request buffer: {why}");
        return None;
    }
    let content_str: String = match String::from_utf8(content_raw) {
        Err(why) => {
            println!("Error parsing content string: {why}");
            return None;
        }
        Ok(string) => string,
    };
    if content_type == "application/json" {
        let id_json: IdMessage = serde_json::from_str(&content_str).unwrap();
        let id_b64: String = id_json.id_b64;
        let id: Id = decode_block(&id_b64).unwrap();
        match log
            .lock()
            .unwrap()
            .search(|x: &Reid| id_equal(x.get_id(), id.clone()))
        {
            None => {
                println!("Could not find reid with id");
                let response_body = "{\"reid\": \"null\"}";
                Some(format!(
                    "HTTP/1.1 200 OK\r\n\nContent-Type: application/json\r\n\nContent-Length: {}\r\n\nConnection: close\r\n\n\r\n\n{}",
                    response_body.len(),
                    response_body,
                ))
            }
            Some(reid) => {
                let reid_b64: String = reid.encode();
                let response_body = format!("{{\"reid\": \"{reid_b64}\"}}");
                Some(format!(
                    "HTTP/1.1 200 OK\r\n\nContent-Type: application/json\r\n\nContent-Length: {}\r\n\nConnection: close\r\n\n\r\n\n{}",
                    response_body.len(),
                    response_body,
                ))
            }
        }
    } else {
        println!("Received content_type: {content_type} that is not yet handled");
        let response_body = "{\"reid\": \"null\"}";
        Some(format!(
            "HTTP/1.1 200 OK\r\n\nContent-Type: application/json\r\n\nContent-Length: {}\r\n\nConnection: close\r\n\n\r\n\n{}",
            response_body.len(),
            response_body,
        ))
    }
}
