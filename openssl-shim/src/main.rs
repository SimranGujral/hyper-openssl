extern crate env_logger;
extern crate hyper;
extern crate hyper_openssl;
extern crate time;
#[macro_use]
extern crate lazy_static;


use std::env;
use std::net::SocketAddr;
use std::io::{Write, Read};
use std::process;
use hyper_openssl::{OpensslClient};
use std::path::PathBuf;
use hyper_openssl::openssl::ssl::{SSL_OP_NO_COMPRESSION, SSL_OP_NO_SSLV2, SSL_OP_NO_SSLV3,SSL_VERIFY_PEER};
use hyper_openssl::openssl::ssl::{self, SslConnectorBuilder, SslContextBuilder, SslMethod, SslContext, Ssl, HandshakeError};
use hyper::net::{NetworkConnector, HttpsStream, HttpStream, SslClient};
use hyper::error::{Result as HyperResult, Error as HyperError};
use std::io;
use std::net::TcpStream;
use std::time::{Duration,Instant};
//use time;

static BOGO_NACK: i32 = 89;
pub type Connector= HttpsConnector;
#[derive(Debug)]
struct Options {
    port: u16,
    server: bool,
    resumes: usize,
    require_any_client_cert: bool, // #ToDo
    offer_no_client_cas: bool, //#ToDo
    tickets: bool, // #ToDo
    queue_data: bool, //#ToDo
    host_name: String,
    key_file: String,
    cert_file: String,
    protocols: Vec<String>, //#ToDo
    support_tls13: bool,
    support_tls12: bool,
    //min_version: Option<ProtocolVersion>, // #ToDo
    //max_version: Option<ProtocolVersion>, // #ToDo
    expect_curve: u16, // #ToDo
}

impl Options {
    fn new() -> Options {
        Options {
            port: 0,
            server: false,
            resumes: 0,
            tickets: true,
            host_name: "example.com".to_string(),
            queue_data: false,
            require_any_client_cert: false,
            offer_no_client_cas: false,
            key_file: "".to_string(),
            cert_file: "".to_string(),
            protocols: vec![],
            support_tls13: true,
            support_tls12: true,
            //min_version: None,
            //max_version: None,
            expect_curve: 0,
        }
    }
 }   

fn make_client_config(opts:&Options)->OpensslClient{
    let mut ssl_connector_builder = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
    {	
    	let ca_file = "/Users/sgujral/Desktop/parallel_cert/hyper-openssl/openssl-shim/certs";
        let context = ssl_connector_builder.builder_mut();
        let context_time = Instant::now();
        context.set_ca_file(&ca_file).expect("could not set CA file");
        let dur = context_time.elapsed();
        println!("setting certificates {} ns", dur.subsec_nanos());
        let cipher_set_time = Instant::now();
        context.set_cipher_list(DEFAULT_CIPHERS).expect("could not set ciphers");
        let dur_cipher = cipher_set_time.elapsed();
        println!("Time for setting ciphers {} ns", dur_cipher.subsec_nanos());

        let options_time = Instant::now();
        context.set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 | SSL_OP_NO_COMPRESSION);
        let dur_options = options_time.elapsed();
        println!("Set options {} ns", dur_options.subsec_nanos());
    }
    let options_connector = Instant::now();
    let ssl_connector = ssl_connector_builder.build();
    let dur_connector = options_connector.elapsed();
    println!("Time to create an ssl connector {} ns", dur_connector.subsec_nanos());

	OpensslClient::from(ssl_connector)
}

pub struct HttpsConnector{
	ssl:OpensslClient,
}
impl HttpsConnector {
    fn new(ssl: OpensslClient) -> HttpsConnector {
        HttpsConnector {
            ssl: ssl,
        }
    }
}
impl NetworkConnector for HttpsConnector {
    type Stream = HttpsStream<<OpensslClient as SslClient>::Stream>;

    fn connect(&self, host: &str, port: u16, scheme: &str) -> HyperResult<Self::Stream> {
        if scheme != "http" && scheme != "https" {
            return Err(HyperError::Io(io::Error::new(io::ErrorKind::InvalidInput,
                                                     "Invalid scheme for Http")));
        }

        // Perform host replacement when making the actual TCP connection.
        let ipv4_time = Instant::now();
        let addr = lookup_ipv4(host,port);
        let dur = ipv4_time.elapsed();
        println!("duration for ipv4 lookup {} ns",dur.subsec_nanos());
        
        let stream_time = Instant::now();
        let stream = HttpStream(try!(TcpStream::connect(&addr)));
        let dur_stream = stream_time.elapsed();
        println!("Time for stream creation {} ns", dur_stream.subsec_nanos());
        //println!("hostname verification");

        if scheme == "http" {
            Ok(HttpsStream::Http(stream))
        } else {
            self.ssl.wrap_client(stream, host).map(HttpsStream::Https)
        }
    }
}

fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;
    println!("Finding socket address");
    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }
	unreachable!("Cannot lookup address");
}

fn make_https_connector(ssl_client: OpensslClient)-> Connector{
	let https_connector = HttpsConnector::new(ssl_client);
	https_connector
}
fn main() {
    let mut args: Vec<_> = env::args().collect();
    env_logger::init().unwrap();

    args.remove(0);
    println!("options: {:?}", args);

    let mut opts = Options::new();
    while !args.is_empty() {
        let arg = args.remove(0);
        match arg.as_ref() {
            "-port" => {
                opts.port = args.remove(0).parse::<u16>().unwrap();
            }
            "-server" => {
                opts.server = true;
            }
            "-key-file" => {
                opts.key_file = args.remove(0);
            }
            "-cert-file" => {
                opts.cert_file = args.remove(0);
            }
            "-resume-count" => {
                opts.resumes = args.remove(0).parse::<usize>().unwrap();
            }
            "-host-name" => {
                opts.host_name = args.remove(0);
            }
            /*
            "-no-tls13" => {
                opts.support_tls13 = false; // specific to implementation, probably make this true
            }
            "-no-tls12" => {
                opts.support_tls12 = false; // specific to implementation, make this true
            }*/
            "-no-tls13"|
            "-no-tls12"|
            "-min-version" |
            "-max-version" |
            "-max-cert-list" |
            "-expect-curve-id" |
            "-expect-peer-signature-algorithm" |
            "-expect-advertised-alpn" |
            "-expect-alpn" |
            "-expect-server-name" |
            "-expect-certificate-types"|
            // ToDo: This needs to be implemented
            "-select-alpn" |
            "-require-any-client-certificate"|
            "-shim-writes-first" |
            "-advertise-alpn"|
            "-use-null-client-ca-list"
            => {
                println!("not checking {} {}; NYI", arg, args.remove(0));
            }
            /*
            "-select-alpn" => {
                opts.protocols.push(args.remove(0));
            }
            "-require-any-client-certificate" => {
                opts.require_any_client_cert = true;
            }
            "-shim-writes-first" => {
                opts.queue_data = true;
            }
            "-host-name" => {
                opts.host_name = args.remove(0); // used this
            }
            /*"-advertise-alpn" => {
                opts.protocols = split_protocols(&args.remove(0));
            }*/
            "-use-null-client-ca-list" => {
                opts.offer_no_client_cas = true;
            }
            */

            // defaults:
            "-enable-all-curves" |
            "-renegotiate-ignore" |
            "-no-tls11" |
            "-no-tls1" |
            "-no-ssl3" |
            "-decline-alpn" |
            "-expect-no-session" |
            "-expect-session-miss" |
            "-expect-extended-master-secret" |
            "-expect-ticket-renewal" |
            // internal openssl details:
            "-async" |
            "-implicit-handshake" |
            "-use-old-client-cert-callback" |
            "-use-early-callback" => {}

            // Not implemented things
            "-dtls" | // this is probably there as a type in open ssl check on that ---exists
            "-enable-ocsp-stapling" | //exists
            "-cipher" |
            "-psk" |
            "-renegotiate-freely" |   //check
            "-false-start" | 
            "-fallback-scsv" | //disabled checks
            "-fail-early-callback" |
            "-fail-cert-callback" |
            "-install-ddos-callback" |
            "-enable-signed-cert-timestamps" |
            "-ocsp-response" |
            "-advertise-npn" |
            "-verify-fail" |
            "-verify-peer" |
            "-expect-channel-id" |
            "-shim-shuts-down" |
            "-check-close-notify" |
            "-send-channel-id" |
            "-select-next-proto" |
            "-p384-only" |
            "-expect-verify-result" |
            "-send-alert" |
            "-signing-prefs" |
            "-digest-prefs" |
            "-export-keying-material" |
            "-use-exporter-between-reads" |
            "-ticket-key" |
            "-tls-unique" |
            "-enable-server-custom-extension" |
            "-enable-client-custom-extension" |
            "-expect-dhe-group-size" |
            "-use-ticket-callback" |
            "-enable-grease" |
            "-enable-channel-id" |
            "-expect-resume-curve-id" |
            "-resumption-delay" |
            "-expect-early-data-info" |
            "-enable-early-data" |
            "-expect-cipher-aes" |
            "-retain-only-sha256-client-cert-initial" |
            "-expect-peer-cert-file" |
            "-signed-cert-timestamps"|
            "rsa_chain_cert.pem"|
            "-enable-short-header" => {
                println!("NYI option {:?}", arg);
                process::exit(BOGO_NACK);
            }

            _ => {
                println!("unhandled option {:?}", arg);
                process::exit(1);
                //process::exit(0);
            }
        }
    }
    // #Uncomment this later
    println!("opts {:?}", opts);
    
    println!("*********** Client creation time **************");
    let client_creation_time = Instant::now();
    let client = make_client_config(&opts);
    let dur = client_creation_time.elapsed();
    println!("****** Client creation time {} ns********", dur.subsec_nanos());
    
    let connector = make_https_connector(client);
    let host = &opts.host_name.as_str();
    let port = opts.port;
    let scheme = "http";

    println!("******Connection Time************* ");
    let connect_time = Instant::now();
    let mut stream = connector.connect(host, port, &scheme).unwrap();
    let dur = connect_time.elapsed();
    println!("*********connection time {} ns******", dur.subsec_nanos());

    let httpreq = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: \
                               close\r\nAccept-Encoding: identity\r\n\r\n",
                              &opts.host_name);
    stream.write_all(httpreq.as_bytes()).unwrap();
    let mut res = vec![];
    stream.read_to_end(&mut res);
    println!("{}", String::from_utf8_lossy(&res));




    //println!("moving to establishing a connection");
    /*
    This represents a single TLS server session.
    Send TLS-protected data to the peer using the io::Write trait implementation. Read data from the peer using the io::Read trait implementation.
    */

    /*for _ in 0..opts.resumes + 1 {
        if opts.server {
            exec_server(&opts, pkcs12.as_ref().unwrap());
            //println!("One run");
        } else {
            exec_client(&opts, connector.as_ref().unwrap());
            //exec_client(&opts);
        }
    }*/
}
// The basic logic here is to prefer ciphers with ECDSA certificates, Forward
// Secrecy, AES GCM ciphers, AES ciphers, and finally 3DES ciphers.
// A complete discussion of the issues involved in TLS configuration can be found here:
// https://wiki.mozilla.org/Security/Server_Side_TLS
const DEFAULT_CIPHERS: &'static str = concat!(
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
    "DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:",
    "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:",
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:",
    "ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:",
    "DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:",
    "ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:",
    "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"
);
