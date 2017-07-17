use std::fs;
use std::fs::File;
use std::sync::Arc;
use std::path::Path;
use std::io;
use std::io::{Write, Read, stdout};
use std::net::TcpStream;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::io::BufReader;
use std::net;

extern crate hyper_openssl;
//use hyper_openssl::HttpsConnector;
use hyper_openssl::{InnerStream};
use hyper_openssl::SslStream as HyperStream;

extern crate openssl;
use openssl::ssl::{SslRef, SSL_VERIFY_PEER, SSL_VERIFY_NONE, SSL_OP_NO_COMPRESSION, SSL_OP_NO_SSLV2, SSL_OP_NO_SSLV3};
use openssl::x509::X509StoreContextRef;
//use hyper::Uri;
use openssl::ssl::{Ssl ,SslContext, SslContextBuilder, SslMethod};

extern crate hyper;
use hyper::net::{NetworkConnector, HttpStream, HttpsStream, SslClient} ;
use hyper::error::{Result as HyperResult, Error as HyperError};

/*use hyper::Client;
use hyper::client::HttpConnector;
use hyper::StatusCode;*/
extern crate antidote;
use antidote::Mutex;
extern crate tokio_core;
use tokio_core::reactor::Core;
use rustls::Session;

extern crate rustls;
//extern crate webpki_roots;
//extern crate webpki;

type Connector = HttpsConnector;

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

#[derive(Clone)]
pub struct HttpsConnector {
    ssl: OpenSslClient,
}

impl HttpsConnector {
    fn new(ssl: OpenSslClient) -> HttpsConnector {
        HttpsConnector {
            ssl: ssl,
        }
    }

    /*fn connect(&self, host: &str, port: u16, scheme: &str) -> HyperResult<openssl::ssl::SslStream<HttpStream>> {
        let addr = lookup_ipv4(host,port);
        let stream_time = Instant::now();
        let stream = HttpStream(try!(TcpStream::connect(&addr)));
        self.ssl.wrap_client(stream, host)//.map(HttpsStream::Https)
        
    }*/
}

impl NetworkConnector for HttpsConnector {
    type Stream = HttpsStream<<OpenSslClient as SslClient>::Stream>;

    fn connect(&self, host: &str, port: u16, scheme: &str) -> HyperResult<Self::Stream> {
        if scheme != "http" && scheme != "https" {
            return Err(HyperError::Io(io::Error::new(io::ErrorKind::InvalidInput,
                                                     "Invalid scheme for Http")));
        }

        // Perform host replacement when making the actual TCP connection.
        let addr = lookup_ipv4(host,port);
        println!("addr {} ",addr);
        let stream = HttpStream(try!(TcpStream::connect(addr)));

        if scheme == "http" {
            Ok(HttpsStream::Http(stream))
        } else {
            // Do not perform host replacement on the host that is used
            // for verifying any SSL certificate encountered.:
            self.ssl.wrap_client(stream, host).map(HttpsStream::Https)
        }
}
}
fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;
    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }
    unreachable!("Cannot lookup address");
}

fn duration_nanos(d: Duration) -> f64 {
    (d.as_secs() as f64) + (d.subsec_nanos() as f64) / 1e9
}

fn create_Client(core: &Core) -> OpenSslClient
{	
	// TODO: Change the path to be in the same folder
	let ca_file = "/Users/sgujral/Desktop/parallel_cert/hyper-openssl/openssl-shim/certs"; 
	let mut context = SslContextBuilder::new(SslMethod::tls()).unwrap();
	context.set_ca_file(&ca_file).expect("could not set CA file");
	context.set_cipher_list(DEFAULT_CIPHERS).unwrap();
	context.set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 | SSL_OP_NO_COMPRESSION);
	let ssl_connector = OpenSslConnector { 
        context: Arc::new(context.build()) 
	};
	let ssl_client = OpenSslClient {
        connector: Arc::new(ssl_connector),
    };
	ssl_client

}

#[derive(Clone)]
pub struct OpenSslConnector{
    context: Arc<SslContext>, 
}

impl OpenSslConnector {

    pub fn connect(&self, domain: &str, stream: HttpStream) -> HyperResult<openssl::ssl::SslStream<HttpStream>>{
        let mut ssl = Ssl::new(&self.context).unwrap();
        ssl.set_hostname(domain).unwrap(); //#Imp: Sets the host name to be used with SNI (Server Name Indication).
        let domain = domain.to_owned();
        
        let verify_call_dur = Instant::now();
        ssl.set_verify_callback(SSL_VERIFY_PEER,
                move |p, x| verify::verify_callback(&domain, p, x));
        let dur = verify_call_dur.elapsed();
        
        println!("{}", dur.subsec_nanos());

        match ssl.connect(stream) {
            Ok(stream) => Ok(stream),
            Err(err) => Err(hyper::Error::Ssl(Box::new(err))),
        }
    }

	pub fn connect_hybrid(&self, domain: &str, stream: HttpStream) -> HyperResult<openssl::ssl::SslStream<HttpStream>>{
        let mut ssl = Ssl::new(&self.context).unwrap();
        ssl.set_hostname(domain).unwrap(); //#Imp: Sets the host name to be used with SNI (Server Name Indication).
        let domain = domain.to_owned();
        
        let verify_call_dur = Instant::now();
        ssl.peer_certificate();
        ssl.set_verify_callback(SSL_VERIFY_PEER,
                move |p, x| verify::verify_callback(&domain, p, x));
        let dur = verify_call_dur.elapsed();
        
        println!("{}", dur.subsec_nanos());

        match ssl.connect(stream) {
            Ok(stream) => Ok(stream),
            Err(err) => Err(hyper::Error::Ssl(Box::new(err))),
        }
    }
}






fn make_https_connector(ssl_client: OpenSslClient)-> Connector{
    let https_connector = HttpsConnector::new(ssl_client);
    https_connector
}

#[derive(Clone)]
pub struct OpenSslClient{
    connector: Arc<OpenSslConnector>,
}

impl SslClient for OpenSslClient {
    //type Stream = HttpsStream<<ServoSslClient as SslClient>::Stream>;
    type Stream = hyper_openssl::SslStream<HttpStream>;
    fn wrap_client(&self, stream: HttpStream, host: &str) -> HyperResult<Self::Stream> {
        match self.connector.connect(host, stream) {
            Ok(stream) => Ok(HyperStream{0: Arc::new(Mutex::new(InnerStream(stream)))}),
            Err(err) => Err(err),
        }
}
}

fn create_rustls_config(core: &Core) -> rustls::ClientConfig{

    let mut config = rustls::ClientConfig::new();
   	let filename ="/Users/sgujral/Desktop/parallel_cert/hyper-openssl/openssl-shim/certs";
	let certfile = fs::File::open(filename).expect("cannot open certificate file");
	let mut reader = BufReader::new(certfile);
	config.root_store.add_pem_file(&mut reader).unwrap();
    /*let len = cfg.root_store.len();
    println!("length of rustls certs: {} ", len);*/ // uses 159 servo certs right now
	//Arc::new(config)
	config
}

fn flush(sess: &mut rustls::Session, conn: &mut net::TcpStream) { 
    while sess.wants_write() {
        sess.write_tls(conn)
            .expect("write failed");
    }
    conn.flush().unwrap();
}

// uses hyper openssl
fn website_bench(site: &str, exp: &Experiment) -> f64 {
    let mut core = Core::new().unwrap();
    let start = Instant::now();
    match *exp {
    	Experiment::OpenSSL => {
    		let client = create_Client(&core);
    		let connector = make_https_connector(client);
    		let port = 443;    
    		let scheme = "https";
    		let mut stream = connector.connect(&site, port, scheme).unwrap();
    		let httpreq = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: \
                               close\r\nAccept-Encoding: identity\r\n\r\n",
                              site);
    		stream.write_all(httpreq.as_bytes()).unwrap();
    		let mut res = vec![];
    		stream.read_to_end(&mut res);
    		// to avoid printing site content
    		//println!("{}", String::from_utf8_lossy(&res));
    	},
    	Experiment::Rustls => {
				let mut config = create_rustls_config(&core);
    			//println!("{}", addr);
				let mut client = rustls::ClientSession::new(&Arc::new(config), site);
    			let httpreq = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: \
                               close\r\nAccept-Encoding: identity\r\n\r\n",
                              site);
    			client.write(httpreq.as_bytes()).unwrap();
    			    			let port = 443;  
    			let addr = lookup_ipv4(site, port);
				let mut sock = TcpStream::connect(addr).unwrap();
		    	loop {
	    	    	let (rl, wl) = client.complete_io(&mut sock).unwrap();
	        		if rl == 0 && wl == 0 {
	            		//println!("EOF");
	            		break;
        			}
	       			let mut plaintext = [0u8; 128];
			        let len = client.read(&mut plaintext).unwrap();
					for b in plaintext.iter_mut() {
            			*b ^= 0xff;
					}
					// FIXME
					// this writes garbage.. but has been individually tested with read_to_end and fetches all websites
			        //stdout().write_all(&plaintext[..len]).unwrap(); 
			        //println!("{}", String::from_utf8_lossy(&plaintext));

			        //Approach 1: Gives plaintext, but failes due to close notify alert recieved. 
			        //this is a type of TLS alert (enum). but is not handled by read_to_end
			        //let mut plaintext = Vec::new(); // this collects intelligible data
			        //tls.read_to_end(&mut plaintext).unwrap(); // fails because of connection being aborted
			        //stdout().write_all(&plaintext).unwrap(); 
					};
  		},
    	Experiment::Hybrid => {
    		println!("unhandled option");
    	},
    	Experiment::DANGEROUS => {
    		println!("unhandled option");
    	},

	};
	duration_nanos(Instant::now().duration_since(start))

}

fn run(trials: i32, sites: &str, exp: &Experiment) -> Vec<f64> {
    let mut times: Vec<f64> = vec!();
    for line in sites.lines() {
        //TODO fix sites.txt
        let l: Vec<String> = line.split(',').map(|s| s.to_string()).collect();
        let mut site = "".to_owned();
        site.push_str(l[0].trim());

        println!("{}", site);

        let mut site_time: Vec<f64> = vec!();
        for _ in 0..trials {
            site_time.push(
                website_bench(&site, &exp));
        }
        let avg = site_time.iter().fold(0.0, |a, &b| a + b)/(site_time.len() as f64);
        times.push(avg);
    }
    times
}

enum Experiment {
    OpenSSL,
    Hybrid,
    DANGEROUS,
    Rustls,
}

fn main(){

	let mut file = match File::open(Path::new("/Users/sgujral/Desktop/parallel_cert/hyper-openssl/examples/sites.txt")) {
        	Err(_) => panic!("sites.txt not found"),
        	Ok(file) => file,
		};
	let mut sites = String::new();
	file.read_to_string(&mut sites).unwrap();

    println!("Average times for dangerous connection (ns)");
    for t in run(1, &sites, &Experiment::Rustls) {
        println!("{}", t);
}
}



//For OpenSSL verification
mod verify {
    use std::net::IpAddr;
    use std::str;

    use openssl::nid;
    use openssl::x509::{X509StoreContextRef, X509Ref, X509NameRef, GeneralName};
    use openssl::stack::Stack;

    pub fn verify_callback(domain: &str,
                           preverify_ok: bool,
                           x509_ctx: &X509StoreContextRef)
                           -> bool {
        if !preverify_ok || x509_ctx.error_depth() != 0 {
            return preverify_ok;
        }
        match x509_ctx.current_cert(){ 
                Some(x509) =>verify_hostname(domain, &x509),
                None => true,
        }
}

    fn verify_hostname(domain: &str, cert: &X509Ref) -> bool {
        match cert.subject_alt_names() {

            Some(names) => verify_subject_alt_names(domain, names),
            None => verify_subject_name(domain, &cert.subject_name()),
        }
    }
    fn verify_subject_alt_names(domain: &str, names: Stack<GeneralName>) -> bool {
        let ip = domain.parse();

        for name in &names {
            match ip {
                Ok(ip) => {
                    if let Some(actual) = name.ipaddress() {
                        if matches_ip(&ip, actual) {
                            return true;
                        }
                    }
                }
                Err(_) => {
                    if let Some(pattern) = name.dnsname() {
                        if matches_dns(pattern, domain, false) {
                            return true;
                        }
                    }
                }
            }
        }

        false
}

    fn verify_subject_name(domain: &str, subject_name: &X509NameRef) -> bool {
        if let Some(pattern) = subject_name.entries_by_nid(nid::COMMONNAME).next() {
            let pattern = match str::from_utf8(pattern.data().as_slice()) {
                Ok(pattern) => pattern,
                Err(_) => return false,
            };

            // Unlike with SANs, IP addresses in the subject name don't have a
            // different encoding. We need to pass this down to matches_dns to
            // disallow wildcard matches with bogus patterns like *.0.0.1
            let is_ip = domain.parse::<IpAddr>().is_ok();

            if matches_dns(&pattern, domain, is_ip) {
                return true;
            }
        }

        false
    }


    fn matches_dns(mut pattern: &str, mut hostname: &str, is_ip: bool) -> bool {
        // first strip trailing . off of pattern and hostname to normalize
        if pattern.ends_with('.') {
            pattern = &pattern[..pattern.len() - 1];
        }
        if hostname.ends_with('.') {
            hostname = &hostname[..hostname.len() - 1];
        }

        matches_wildcard(pattern, hostname, is_ip).unwrap_or_else(|| pattern == hostname)
}

    fn matches_wildcard(pattern: &str, hostname: &str, is_ip: bool) -> Option<bool> {
        // IP addresses and internationalized domains can't involved in wildcards
        if is_ip || pattern.starts_with("xn--") {
            return None;
        }

        let wildcard_location = match pattern.find('*') {
            Some(l) => l,
            None => return None,
        };

        let mut dot_idxs = pattern.match_indices('.').map(|(l, _)| l);
        let wildcard_end = match dot_idxs.next() {
            Some(l) => l,
            None => return None,
        };

        // Never match wildcards if the pattern has less than 2 '.'s (no *.com)
        //
        // This is a bit dubious, as it doesn't disallow other TLDs like *.co.uk.
        // Chrome has a black- and white-list for this, but Firefox (via NSS) does
        // the same thing we do here.
        //
        // The Public Suffix (https://www.publicsuffix.org/) list could
        // potentially be used here, but it's both huge and updated frequently
        // enough that management would be a PITA.
        if dot_idxs.next().is_none() {
            return None;
        }

        // Wildcards can only be in the first component
        if wildcard_location > wildcard_end {
            return None;
        }

        let hostname_label_end = match hostname.find('.') {
            Some(l) => l,
            None => return None,
        };

        // check that the non-wildcard parts are identical
        if pattern[wildcard_end..] != hostname[hostname_label_end..] {
            return Some(false);
        }

        let wildcard_prefix = &pattern[..wildcard_location];
        let wildcard_suffix = &pattern[wildcard_location + 1..wildcard_end];

        let hostname_label = &hostname[..hostname_label_end];

        // check the prefix of the first label
        if !hostname_label.starts_with(wildcard_prefix) {
            return Some(false);
        }

        // and the suffix
        if !hostname_label[wildcard_prefix.len()..].ends_with(wildcard_suffix) {
            return Some(false);
        }

        Some(true)
}


    fn matches_ip(expected: &IpAddr, actual: &[u8]) -> bool {
        match (expected, actual.len()) {
            (&IpAddr::V4(ref addr), 4) => actual == addr.octets(),
            (&IpAddr::V6(ref addr), 16) => {
                let segments = [((actual[0] as u16) << 8) | actual[1] as u16,
                                ((actual[2] as u16) << 8) | actual[3] as u16,
                                ((actual[4] as u16) << 8) | actual[5] as u16,
                                ((actual[6] as u16) << 8) | actual[7] as u16,
                                ((actual[8] as u16) << 8) | actual[9] as u16,
                                ((actual[10] as u16) << 8) | actual[11] as u16,
                                ((actual[12] as u16) << 8) | actual[13] as u16,
                                ((actual[14] as u16) << 8) | actual[15] as u16];
                segments == addr.segments()
            }
            _ => false,
        }
}
}
