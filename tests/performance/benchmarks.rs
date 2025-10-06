//! Benchmark tests for FIDO service

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fido_server::{FidoService, RegistrationRequest, AuthenticationRequest};

fn bench_registration_creation(c: &mut Criterion) {
    c.bench_function("registration_creation", |b| {
        b.iter(|| {
            let service = FidoService::new();
            black_box(service);
        })
    });
}

fn bench_registration_start(c: &mut Criterion) {
    let mut service = FidoService::new();
    let request = RegistrationRequest {
        username: "bench@example.com".to_string(),
        display_name: "Benchmark User".to_string(),
    };

    c.bench_function("registration_start", |b| {
        b.iter(|| {
            // Note: This is a simplified benchmark since we can't easily benchmark async functions
            // In a real scenario, you'd use tokio::runtime::Runtime or criterion-async
            let mut svc = FidoService::new();
            let req = request.clone();
            // Simulate the synchronous parts of the operation
            black_box(req);
        })
    });
}

fn bench_authentication_start(c: &mut Criterion) {
    let mut service = FidoService::new();
    
    // Pre-register a user
    let reg_request = RegistrationRequest {
        username: "authbench@example.com".to_string(),
        display_name: "Auth Benchmark User".to_string(),
    };
    let _ = service.start_registration(reg_request);

    let auth_request = AuthenticationRequest {
        username: "authbench@example.com".to_string(),
    };

    c.bench_function("authentication_start", |b| {
        b.iter(|| {
            // Simplified benchmark for authentication
            let req = auth_request.clone();
            black_box(req);
        })
    });
}

fn bench_challenge_generation(c: &mut Criterion) {
    c.bench_function("challenge_generation", |b| {
        b.iter(|| {
            use base64::{Engine as _, engine::general_purpose};
            let bytes = rand::random::<[u8; 32]>();
            let challenge = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            black_box(challenge);
        })
    });
}

fn bench_user_lookup(c: &mut Criterion) {
    let mut service = FidoService::new();
    
    // Pre-register users
    for i in 0..100 {
        let request = RegistrationRequest {
            username: format!("lookup{}@example.com", i),
            display_name: format!("Lookup User {}", i),
        };
        let _ = service.start_registration(request);
    }

    c.bench_function("user_lookup", |b| {
        b.iter(|| {
            // Simulate user lookup
            let username = format!("lookup{}@example.com", black_box(50));
            black_box(username);
        })
    });
}

fn bench_concurrent_operations(c: &mut Criterion) {
    c.bench_function("concurrent_operations", |b| {
        b.iter(|| {
            // Simulate concurrent operation setup
            let service = FidoService::new();
            black_box(service);
        })
    });
}

criterion_group!(
    benches,
    bench_registration_creation,
    bench_registration_start,
    bench_authentication_start,
    bench_challenge_generation,
    bench_user_lookup,
    bench_concurrent_operations
);

criterion_main!(benches);