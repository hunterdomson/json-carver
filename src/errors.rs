use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Err {
    #[error("I/O operation failed")]
    StreamError(#[from] io::Error),
}
