use graphlog_proto::utils::http_server::HttpServer;

fn main() {
    let addr_port = String::from("127.0.0.1:7878");
    let mut http_server = HttpServer::new(addr_port, 1);
    http_server.run();
}
