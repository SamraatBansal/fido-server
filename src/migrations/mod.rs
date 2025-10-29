#![allow(dead_code)]

pub const MIGRATIONS: diesel::migrations::EmbeddedMigrations = diesel::migrations::embed_migrations!("migrations");