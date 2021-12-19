use async_trait::async_trait;
use futures::AsyncRead;
use futures::AsyncWrite;
use quinn::{RecvStream, SendStream};
use std::io::{IoSlice, IoSliceMut};
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;
use xtra::Actor;

pub fn handle_protocol(negotiated_protocol: &str, send: SendStream, recv: RecvStream) {
    println!("Successfully negotiated protocol: {}", negotiated_protocol);

    match negotiated_protocol {
        PingActor::PROTOCOL => {
            let (addr, fut) = PingActor::new(send, recv).create(None).run();
            mem::forget(addr);
            tokio::spawn(fut);
        }
        other => {
            eprintln!("Negotiated unsupported protocol: '{}'", other)
        }
    }
}

pub struct BiStream<'a> {
    send: &'a mut SendStream,
    recv: &'a mut RecvStream,
}

impl<'a> BiStream<'a> {
    pub fn new(send: &'a mut SendStream, recv: &'a mut RecvStream) -> Self {
        BiStream { send, recv }
    }
}

impl<'a> AsyncRead for BiStream<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncRead::poll_read(Pin::new(self.recv), cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<std::io::Result<usize>> {
        AsyncRead::poll_read_vectored(Pin::new(self.recv), cx, bufs)
    }
}
impl<'a> AsyncWrite for BiStream<'a> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(self.send), cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write_vectored(Pin::new(self.send), cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(self.send), cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_close(Pin::new(self.send), cx)
    }
}

pub struct PingActor {
    send: SendStream,
    /// None after initialized.
    recv: Option<RecvStream>,
}

impl PingActor {
    pub const PROTOCOL: &'static str = "/ping/1.0.0";

    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv: Some(recv),
        }
    }
}

#[async_trait]
impl xtra::Actor for PingActor {
    async fn started(&mut self, ctx: &mut xtra::Context<Self>) {
        let mut recv = BufReader::new(self.recv.take().expect("must be `Some` after init")).lines();
        let this = ctx.address().expect("we just started");

        tokio::spawn(async move {
            while let Some(line) = recv.next_line().await? {
                match line.as_str() {
                    "PONG" => {
                        this.send(PongReceived).await?;
                    }
                    "PING" => {
                        this.send(PingReceived).await?;
                    }
                    other => {
                        eprintln!("Unknown message: '{}'", other)
                    }
                }
            }

            anyhow::Ok(())
        });

        tokio::spawn(
            ctx.notify_interval(Duration::from_secs(5), || SendPing)
                .expect("we just started"),
        );
    }
}

#[async_trait]
impl xtra::Handler<PongReceived> for PingActor {
    async fn handle(&mut self, _: PongReceived, _: &mut xtra::Context<Self>) {
        println!("Received PONG!");
    }
}

#[async_trait]
impl xtra::Handler<PingReceived> for PingActor {
    async fn handle(&mut self, _: PingReceived, _: &mut xtra::Context<Self>) {
        println!("Received PING!");
        if let Err(e) = self.send.write_all(b"PONG\n").await {
            eprintln!("Failed to write PING: {}", e);
        }
    }
}

#[async_trait]
impl xtra::Handler<SendPing> for PingActor {
    async fn handle(&mut self, _: SendPing, _: &mut xtra::Context<Self>) {
        if let Err(e) = self.send.write_all(b"PING\n").await {
            eprintln!("Failed to write PING: {}", e);
        }
    }
}

struct PongReceived;

impl xtra::Message for PongReceived {
    type Result = ();
}

struct PingReceived;

impl xtra::Message for PingReceived {
    type Result = ();
}

struct SendPing;

impl xtra::Message for SendPing {
    type Result = ();
}
