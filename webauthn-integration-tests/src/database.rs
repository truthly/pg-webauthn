use anyhow::{Context, Result};
use postgres::{Client, NoTls, Row};
use std::env;

pub struct TestDatabase {
    client: Client,
    db_name: String,
    should_cleanup: bool,
    debug: bool,
}

impl TestDatabase {
    pub fn new() -> Result<Self> {
        let user = env::var("USER").context("USER environment variable not set")?;
        let db_name = format!("webauthn_test_{}", rand::random::<u32>());

        // Connect to postgres database to create test database
        let mut client = Client::connect(
            &format!("host=localhost port=5432 user={} dbname=postgres", user),
            NoTls,
        ).context("Failed to connect to PostgreSQL")?;

        // Create test database
        client.execute(
            &format!("CREATE DATABASE {}", db_name),
            &[],
        ).context("Failed to create test database")?;

        // Disconnect from postgres and connect to test database
        drop(client);

        let mut client = Client::connect(
            &format!("host=localhost port=5432 user={} dbname={}", user, db_name),
            NoTls,
        ).context("Failed to connect to test database")?;

        // Install webauthn extension
        client.execute(
            "CREATE EXTENSION IF NOT EXISTS webauthn CASCADE",
            &[],
        ).context("Failed to create webauthn extension")?;

        println!("  Created database: {}", db_name);

        Ok(Self {
            client,
            db_name,
            should_cleanup: true,
            debug: false,
        })
    }

    pub fn client(&mut self) -> &mut Client {
        &mut self.client
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    /// Execute a query with debug output if enabled
    #[allow(dead_code)]
    pub fn debug_execute(&mut self, query: &str, params: &[&(dyn postgres::types::ToSql + Sync)]) -> Result<u64> {
        if self.debug {
            self.print_sql_debug(query, params);
        }
        self.client.execute(query, params)
            .context("Failed to execute query")
    }

    /// Execute a query returning one row with debug output if enabled
    pub fn debug_query_one(&mut self, query: &str, params: &[&(dyn postgres::types::ToSql + Sync)]) -> Result<Row> {
        if self.debug {
            self.print_sql_debug(query, params);
        }
        self.client.query_one(query, params)
            .context("Failed to execute query")
    }

    /// Execute a query returning optional row with debug output if enabled
    #[allow(dead_code)]
    pub fn debug_query_opt(&mut self, query: &str, params: &[&(dyn postgres::types::ToSql + Sync)]) -> Result<Option<Row>> {
        if self.debug {
            self.print_sql_debug(query, params);
        }
        self.client.query_opt(query, params)
            .context("Failed to execute query")
    }

    fn print_sql_debug(&self, query: &str, params: &[&(dyn postgres::types::ToSql + Sync)]) {
        println!("\n🔍 DEBUG SQL EXECUTION [Database: {}]:", self.db_name);
        println!("━━━━━━━━━━━━━━━━━━━━━━");
        println!("Query:");
        for line in query.lines() {
            println!("  {}", line.trim());
        }
        println!("\nParameters:");
        for (i, param) in params.iter().enumerate() {
            // Convert parameter to debug string representation
            let param_str = format!("{:?}", param);
            // Truncate very long parameters
            let display = if param_str.len() > 100 {
                format!("{}... (truncated)", &param_str[..100])
            } else {
                param_str
            };
            println!("  ${}: {}", i + 1, display);
        }
        println!("━━━━━━━━━━━━━━━━━━━━━━\n");
    }

    #[allow(dead_code)]
    pub fn disable_cleanup(&mut self) {
        self.should_cleanup = false;
    }

    #[allow(dead_code)]
    pub fn clear_test_data(&mut self) -> Result<()> {
        // Clear all test data from the tables
        self.client.execute("DELETE FROM webauthn.assertions", &[])?;
        self.client.execute("DELETE FROM webauthn.credentials", &[])?;
        self.client.execute("DELETE FROM webauthn.users", &[])?;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.should_cleanup {
            return Ok(());
        }

        // Disconnect from test database
        let user = env::var("USER").context("USER environment variable not set")?;

        // Create new connection to postgres database to drop test database
        let mut client = Client::connect(
            &format!("host=localhost port=5432 user={} dbname=postgres", user),
            NoTls,
        ).context("Failed to connect to PostgreSQL for cleanup")?;

        // Terminate connections to test database
        client.execute(
            &format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                 WHERE datname = '{}' AND pid <> pg_backend_pid()",
                self.db_name
            ),
            &[],
        ).ok();

        // Drop test database
        client.execute(
            &format!("DROP DATABASE IF EXISTS {}", self.db_name),
            &[],
        ).context("Failed to drop test database")?;

        Ok(())
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("Failed to cleanup test database: {}", e);
        }
    }
}