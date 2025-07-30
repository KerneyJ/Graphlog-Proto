use std::sync::{Arc, Mutex};

use dialoguer::Input;

use graphlog_proto::{
    types::{
        common::{id_equal, Id},
        log::Log,
        reid::Reid,
    },
    utils::http_server::ReidMessage,
};

use openssl::{
    base64::decode_block,
    pkey::{PKey, Public},
};

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    routing::{get, post},
    serve, Router,
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
    let log: Arc<Mutex<Log<Reid>>>;
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
        .route("/publish", post(publish))
        .with_state(Arc::clone(&log))
        .route("/tail", get(tail))
        .with_state(Arc::clone(&log))
        .route("/tail_{num}", get(tail_num))
        .with_state(Arc::clone(&log))
        .route("/{id}", get(lookup))
        .with_state(Arc::clone(&log));

    let listener = TcpListener::bind(addr_port).await.unwrap();
    serve(listener, app).await.unwrap();
}

async fn publish(
    State(log): State<Arc<Mutex<Log<Reid>>>>,
    Json(reid_msg): Json<ReidMessage>,
) -> StatusCode {
    let reid: Reid = reid_msg.reid;
    let pubk_str: String = reid_msg.pub_key;
    let pubk: PKey<Public> = PKey::public_key_from_pem(pubk_str.as_bytes()).unwrap();
    if reid.verify_sig(&pubk) {
        log.lock().unwrap().append(reid);
        println!("Pushed reid to log");
        StatusCode::OK
    } else {
        println!("Could not verify signature");
        StatusCode::NOT_ACCEPTABLE
    }
}

async fn tail(
    State(log): State<Arc<Mutex<Log<Reid>>>>,
) -> Result<Json<Reid>, (StatusCode, String)> {
    match log.lock().unwrap().tail() {
        Some(entry) => Ok(Json(entry.clone())),
        None => Err((StatusCode::NO_CONTENT, "Empty log".to_string())),
    }
}

async fn tail_num(
    Path(num): Path<String>,
    State(log): State<Arc<Mutex<Log<Reid>>>>,
) -> Result<Json<Vec<Reid>>, (StatusCode, String)> {
    if num == "all" {
        Err((StatusCode::NO_CONTENT, "all not implemented".to_string()))
    } else {
        Ok(Json(
            log.lock()
                .unwrap()
                .tailn(num.parse().expect("Couldn't convert to usize")),
        ))
    }
}

async fn lookup(
    Path(id_b64): Path<String>,
    State(log): State<Arc<Mutex<Log<Reid>>>>,
) -> Result<Json<Reid>, (StatusCode, String)> {
    let id: Id = decode_block(&id_b64).unwrap();
    match log
        .lock()
        .unwrap()
        .search(|x: &Reid| id_equal(x.get_id(), id.clone()))
    {
        None => {
            println!("Could not find reid with id");
            Err((
                StatusCode::NO_CONTENT,
                format!("Failed to find Reid with id: {id_b64}"),
            ))
        }
        Some(reid) => {
            println!("Found reid with id: {id_b64}");
            Ok(Json(reid.clone()))
        }
    }
}
