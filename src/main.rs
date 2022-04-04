use std::convert::{From, Into};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::join;
use tokio::net::{TcpListener, TcpStream};

use dns_lookup::lookup_addr;

// RFC for Socks5
// https://www.ietf.org/rfc/rfc1928.txt

enum SocksState {
    AuthSelection,
    Requests,
}

#[derive(PartialEq, Clone, Copy)]
enum AuthMethod {
    NoAuthentication = 0,
    GSSAPI = 1,
    UsernamePassword = 2,
    IANA,
    PrivateMethod,
    NoAcceptableMethod = 0xFF,
}

impl From<u8> for AuthMethod {
    fn from(integer: u8) -> Self {
        match integer {
            0 => Self::NoAuthentication,
            1 => Self::GSSAPI,
            2 => Self::UsernamePassword,
            3..=0x7F => Self::IANA,
            0x80..=0xFE => Self::PrivateMethod,
            0xFF => Self::NoAcceptableMethod,
        }
    }
}

enum CommandType {
    Connect = 1,
    Bind = 2,
    UdpAssociate = 3,
}

#[derive(Debug)]
enum Atyp {
    Ipv4(Ipv4Addr),
    DomainName(String),
    Ipv6(Ipv6Addr),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:12345").await?;

    loop {
        let (socket, socket_address) = listener.accept().await?;

        tokio::spawn(async move {
            let mut socks_connection = SocksConnection::new(socket, socket_address);

            socks_connection.parse_socks_request().await
        });
    }

}

struct SocksConnection {
    socket: Option<TcpStream>,
    socket_address: SocketAddr,
}

impl SocksConnection {
    fn new(socket: TcpStream, socket_address: SocketAddr) -> Self {
        SocksConnection {
            socket: Some(socket),
            socket_address,
        }
    }

    async fn parse_socks_request(&mut self) -> Result<(), &'static str> {
        let mut buffer = [0; 8192];
        let mut connection_state = SocksState::AuthSelection;

        #[cfg(feature = "debug")]
        {
            eprintln!("New Request | Source: {:?}", self.socket_address);
        }

        loop {
            match self.socket.as_mut().unwrap().read(&mut buffer).await {
                Ok(n) if n == 0 => return Err("socket was closed"),
                Ok(n) => {
                    #[cfg(feature = "debug")]
                    {
                        eprintln!("Read bytes from socket | Bytes: {:?}", n);
                    }
                    n
                }
                Err(e) => {
                    eprintln!("Failed to read from socket | Err = {:?}", e);
                    return Err("failed to read from socket");
                }
            };

            if buffer[0] == 4 {
                #[cfg(feature = "debug")]
                {
                    eprintln!("SOCKS Version 4 Requested");
                }

                self.parse_socks4_request(&buffer).await?;
                return Ok(());
            } else if buffer[0] == 5 {
                #[cfg(feature = "debug")]
                {
                    eprintln!("SOCKS Version 5 Requested");
                }

                match connection_state {
                    SocksState::AuthSelection => {
                        // #[cfg(feature = "debug")]
                        // {
                        //     eprintln!("SocksState::AuthSelection");
                        // }
                        self.parse_socks5_auth_selection(&buffer).await?;

                        connection_state = SocksState::Requests;
                    }
                    SocksState::Requests => {
                        #[cfg(feature = "debug")]
                        {
                            eprintln!("SocksState::Requests");
                        }
                        self.parse_socks5_request(&buffer).await?;
                        return Ok(());
                    }
                }
            } else {
                #[cfg(feature = "debug")]
                {
                    eprintln!("Version mismatch | Version requested : {:?}", buffer[0]);
                }
                return Err("SOCKS Version unsupported!");
            }
        }
    }

    async fn parse_socks4_request(&mut self, buffer: &[u8; 8192]) -> Result<(), &'static str> {

        let _command = match buffer[1] {
            1 => {
                #[cfg(feature = "debug")]
                {
                    eprintln!("CommandType::Connect requested");
                }
                CommandType::Connect
            }
            2 => {
                eprintln!("CommandType::Bind requested");
                unimplemented!("Not yet implemented CommandType");
                CommandType::Bind
            }
            _ => {
                eprintln!(
                    "Command type unsupported | Command requested : {:?}",
                    buffer[1]
                );
                return Err("Command type unsupported!");
            }
        };

        let dst_port = u16::from_be_bytes([buffer[2], buffer[3]]);
        #[cfg(feature = "debug")]
        {
            eprintln!("Destination port requested : {:?}", dst_port);
        }

        let dst_ip = Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7]);
        #[cfg(feature = "debug")]
        {
            eprintln!("Destination IP requested : {:?}", dst_ip);
        }

        let mut end_idx_id = 8;
        loop {
            if buffer[end_idx_id] == 0 {
                break;
            }

            end_idx_id += 1
        }
        let id = std::str::from_utf8(&buffer[8..end_idx_id])
            .map_err(|_| "Unable to convert buffer to UTF8 str")?;
        #[cfg(feature = "debug")]
        {
            eprintln!("ID provided : {:?} | ID Length : {:?}", id, end_idx_id - 8);
        }

        let ip_array = dst_ip.octets();
        let mut domain = None;
        if ip_array[0] == 0 && ip_array[1] == 0 && ip_array[2] == 0 && ip_array[3] != 0 {
            let mut end_idx_domain = end_idx_id + 1;
            loop {
                if buffer[end_idx_domain] == 0 {
                    break;
                }

                end_idx_domain += 1
            }
            domain = Some(
                std::str::from_utf8(&buffer[end_idx_id + 1..end_idx_domain])
                    .map_err(|_| "Unable to convert buffer to UTF8 str")?,
            );
            #[cfg(feature = "debug")]
            {
                eprintln!(
                    "Domain requested : {:?} | Domain name length : {:?}",
                    domain,
                    end_idx_domain - end_idx_id
                );
            }
        }

        #[cfg(feature = "terminal-logging")]
        if let Some(domain_name) = domain {
            println!(
                "New SOCKS4 stream establishing to {}:{} | {}",
                dst_ip, dst_port, domain_name
            );
        } else {
            println!(
                "New SOCKS4 stream establishing to {}:{} | {}",
                dst_ip,
                dst_port,
                lookup_addr(&std::net::IpAddr::V4(dst_ip)).unwrap_or("Unknown".to_string())
            );
        }

        let proxied_connection = if domain.is_some() {
            TcpStream::connect((domain.unwrap(), dst_port)).await
        } else {
            TcpStream::connect((dst_ip, dst_port)).await
        }
        .map_err(|_| "Error connecting to target server")?;

        self.socket
            .as_mut()
            .unwrap()
            .write(&[0, 0x5a, 0x00, 0, 0, 0, 0, 0])
            .await
            .map_err(|_| "failed to write to socket")?;

        self.setup_tunnel(proxied_connection).await?;

        Ok(())
    }

    async fn parse_socks5_request(&mut self, buffer: &[u8; 8192]) -> Result<(), &'static str> {
        let _command = match buffer[1] {
            1 => {
                #[cfg(feature = "debug")]
                {
                    eprintln!("CommandType::Connect requested");
                }
                CommandType::Connect
            }
            2 => {
                eprintln!("CommandType::Bind requested");
                unimplemented!("Not yet implemented CommandType");
                CommandType::Bind
            }
            3 => {
                eprintln!("CommandType::UdpAssociate requested");
                unimplemented!("Not yet implemented CommandType");
                CommandType::UdpAssociate
            }
            _ => {
                eprintln!(
                    "Command type unsupported | Command requested : {:?}",
                    buffer[1]
                );
                return Err("Command type unsupported!");
            }
        };

        let (atyp, dst_port) = match buffer[3] {
            1 => {
                #[cfg(feature = "debug")]
                {
                    eprintln!("Ipv4 Dst.Addr with length of 4");
                }
                (
                    Atyp::Ipv4(Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7])),
                    u16::from_be_bytes([buffer[8], buffer[9]]),
                )
            }
            3 => {
                #[cfg(feature = "debug")]
                {
                    eprintln!("DomainName Dst.Addr with length of {}", buffer[4]);
                }
                (
                    Atyp::DomainName(
                        std::str::from_utf8(&buffer[5..5 + (buffer[4] as usize)])
                            .unwrap()
                            .to_owned(),
                    ),
                    u16::from_be_bytes([
                        buffer[5 + (buffer[4] as usize)],
                        buffer[5 + (buffer[4] as usize) + 1],
                    ]),
                )
            }
            4 => {
                #[cfg(feature = "debug")]
                {
                    eprintln!("Ipv6 Dstt.Addr with length of 16");
                }
                (
                    Atyp::Ipv6(Ipv6Addr::from([
                        buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9],
                        buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15],
                        buffer[16], buffer[17], buffer[18], buffer[19],
                    ])),
                    u16::from_be_bytes([buffer[20], buffer[21]]),
                )
            }
            _ => {
                eprintln!(" Atyp unsupported | Atyp requested : {:?}", buffer[3]);
                return Err("Atyp unsupported!");
            }
        };

        #[cfg(feature = "debug")]
        {
            eprintln!("Atyp : {:?} | Dst port : {}", atyp, dst_port);
        }

        #[cfg(feature = "terminal-logging")]
        match &atyp {
            Atyp::Ipv4(ip_addr) => {
                println!(
                    "New SOCKS5 stream establishing to {}:{} | {}",
                    ip_addr,
                    dst_port,
                    lookup_addr(&std::net::IpAddr::V4(ip_addr.clone()))
                        .unwrap_or("Unknown".to_string())
                );
            }
            Atyp::DomainName(domain_name) => {
                println!(
                    "New SOCKS4 stream establishing to {}:{} | {}",
                    "0.0.0.0", dst_port, domain_name
                );
            }
            Atyp::Ipv6(ip_addr) => {
                println!(
                    "New SOCKS5 stream establishing to {}:{} | {}",
                    ip_addr,
                    dst_port,
                    lookup_addr(&std::net::IpAddr::V6(ip_addr.clone()))
                        .unwrap_or("Unknown".to_string())
                );
            }
        }

        let proxied_connection = match atyp {
            Atyp::Ipv4(ip_addr) => TcpStream::connect((ip_addr, dst_port)).await,
            Atyp::DomainName(domain) => TcpStream::connect((domain, dst_port)).await,
            Atyp::Ipv6(ip_addr) => TcpStream::connect((ip_addr, dst_port)).await,
        }
        .map_err(|_| "Error connecting to target server")?;
        let proxied_port = proxied_connection
            .local_addr()
            .map_err(|_| "Error getting proxied port")?
            .port()
            .to_be_bytes();

        self.socket
            .as_mut()
            .unwrap()
            .write(&[
                0x05,
                0x00,
                0x00,
                0x01,
                127,
                0,
                0,
                1,
                proxied_port[0],
                proxied_port[1],
            ])
            .await
            .map_err(|_| "failed to write to socket")?;

        self.setup_tunnel(proxied_connection).await?;

        Ok(())
    }

    async fn setup_tunnel(&mut self, target_connection: TcpStream) -> Result<(), &'static str> {
        let (self_rx, mut self_tx) = self.socket.take().unwrap().into_split();
        let (target_rx, mut target_tx) = target_connection.into_split();

        let handle_rx = tokio::spawn(async move {
            let mut recv_buffer = [0; 8192];
            loop {
                self_rx
                    .readable()
                    .await
                    .map_err(|_| "self_rx not readable")?;
                match self_rx.try_read(&mut recv_buffer) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        target_tx
                            .write(&recv_buffer[0..n])
                            .await
                            .map_err(|_| "Error while writing to target_tx")?;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err("Error returned from self_rx.try_read"),
                }
            }
        });

        let handle_tx = tokio::spawn(async move {
            let mut send_buffer = [0; 8192];
            loop {
                target_rx
                    .readable()
                    .await
                    .map_err(|_| "target connection socket not readable")?;
                match target_rx.try_read(&mut send_buffer) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        self_tx
                            .write(&send_buffer[0..n])
                            .await
                            .map_err(|_| "Error while writing to client")?;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err("Error returned from target_rx.try_read"),
                }
            }
        });

        let _ = join!(handle_rx, handle_tx);

        Ok(())
    }

    async fn parse_socks5_auth_selection(
        &mut self,
        buffer: &[u8; 8192],
    ) -> Result<(), &'static str> {
        let nmethods = buffer[1];

        let mut accepted_method = None;

        for count in 0..nmethods {
            if let Some(method) = accepted_method {
                if method != AuthMethod::NoAcceptableMethod {
                    break;
                }
            }

            match buffer[2 + count as usize] {
                0 => {
                    #[cfg(feature = "debug")]
                    {
                        eprintln!("No Authentication Requested");
                    }
                    accepted_method = Some(AuthMethod::NoAuthentication);
                }
                1 => {
                    #[cfg(feature = "debug")]
                    {
                        eprintln!("GSSAPI Auth Requested");
                    }
                    // This is unimplemented
                    continue;
                }
                2 => {
                    #[cfg(feature = "debug")]
                    {
                        eprintln!("Username/Password Auth Requested");
                    }
                    // This is unimplemented
                    continue;
                }
                3..=0x7f => {
                    #[cfg(feature = "debug")]
                    {
                        eprintln!("IANA Assigned Auth Requested");
                    }
                    // This is unimplemented
                    continue;
                }
                0x80..=0xFE => {
                    #[cfg(feature = "debug")]
                    {
                        eprintln!("Reserved for Private Methods Auth Requested");
                    }
                    // This is unimplemented
                    continue;
                }
                0xFF => {
                    #[cfg(feature = "debug")]
                    {
                        eprintln!("No Acceptable Methods");
                    }
                    accepted_method = Some(AuthMethod::NoAcceptableMethod);
                }
            };
        }

        let send_buffer: [u8; 2];
        match accepted_method {
            Some(method) => send_buffer = [0x5, method as u8],
            None => send_buffer = [0x5, AuthMethod::NoAcceptableMethod as u8],
        }

        self.socket
            .as_mut()
            .unwrap()
            .write(&send_buffer)
            .await
            .map_err(|_| "failed to write to socket")?;

        Ok(())
    }
}
