#![allow(dead_code)]

pub const MIGRATIONS: diesel_migrations::EmbeddedMigrations = diesel_migrations::embed_migrations!("migrations");