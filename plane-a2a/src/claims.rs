//! The transports this plane's claims name. A claim is the only way a plane names a transport, and
//! it names it as a claim, never as a connection; the claims themselves are the door's
//! ([`crate::door_statement`]).

/// The request transport every one of this plane's document claims is made against.
pub const DOCUMENT_TRANSPORT: &str = "http";

/// The framed transport the newer binding of this protocol is made against.
pub const FRAMED_TRANSPORT: &str = "grpc";
