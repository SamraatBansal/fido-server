//! FIDO2/WebAuthn Relying Party Server
//! 
//! This library provides a complete implementation of a FIDO2/WebAuthn conformant
//! Relying Party Server with comprehensive testing and security features.

pub mod config;
pub mod controllers;
pub mod db;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod schema;
pub mod services;
pub mod utils;

#[cfg(test)]
mod tests;