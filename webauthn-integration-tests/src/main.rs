mod authenticator;
mod database;
mod test_positive;
mod test_negative;
mod utils;
mod verifier;

use anyhow::Result;
use clap::Parser;
use database::TestDatabase;
use std::process;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[clap(author, version, about = "WebAuthn PostgreSQL Integration Tests", long_about = None)]
struct Args {
    /// Number of iterations to run the tests
    #[clap(short = 'n', long, default_value_t = 10)]
    iterations: usize,

    /// Enable debug output for SQL queries
    #[clap(short = 'd', long)]
    debug: bool,
}

fn main() {
    let args = Args::parse();

    match run_tests(args.iterations, args.debug) {
        Ok(_) => {
            println!("\n✅ All tests passed!");
            process::exit(0);
        }
        Err(e) => {
            eprintln!("\n❌ Test suite failed: {}", e);
            process::exit(1);
        }
    }
}

fn run_tests(iterations: usize, debug: bool) -> Result<()> {
    println!("===========================================");
    println!("   WebAuthn PostgreSQL Integration Tests   ");
    println!("===========================================");
    println!("\nTest iterations: {}", iterations);

    // Create test database
    println!("\n📦 Setting up test database...");
    let mut db = TestDatabase::new()?;
    db.disable_cleanup();  // Don't cleanup database after tests
    db.set_debug(debug);
    if debug {
        println!("🔍 Debug mode enabled - SQL queries will be printed");
    }
    println!("✓ Test database created and webauthn extension installed");

    let overall_start = Instant::now();
    let mut iteration_times = Vec::new();

    // Run tests multiple times
    for i in 1..=iterations {
        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  Iteration {}/{}", i, iterations);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        let iteration_start = Instant::now();

        // Run positive tests
        test_positive::run_positive_tests(&mut db, debug)?;

        // Run negative tests
        test_negative::run_negative_tests(&mut db, debug)?;

        let iteration_duration = iteration_start.elapsed();
        iteration_times.push(iteration_duration);

        println!("Iteration {} completed in {:.2}s", i, iteration_duration.as_secs_f64());
    }

    // Print statistics
    let total_time = overall_start.elapsed();
    let avg_time: Duration = Duration::from_secs_f64(
        iteration_times.iter().map(|d| d.as_secs_f64()).sum::<f64>() / iterations as f64
    );

    println!("\n===========================================");
    println!("              Test Statistics              ");
    println!("===========================================");
    println!("Total iterations:    {}", iterations);
    println!("Total time:          {:.2}s", total_time.as_secs_f64());
    println!("Average per iteration: {:.2}s", avg_time.as_secs_f64());
    println!("Tests per iteration: 10 (4 positive, 6 negative)");
    println!("Total tests run:     {}", iterations * 10);

    println!("\n📌 Test database preserved for debugging");
    // Database not cleaned up - disabled cleanup

    Ok(())
}