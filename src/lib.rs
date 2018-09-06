#![deny(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", deny(warnings))]
#![feature(const_str_as_bytes)]
//! # Rocket Csrf
//!
//! A crate to protect you application against csrf.
//!
//! ## Feature
//!
//! - Automatically protect all POST, PUT, DELETE and PATCH endpoints
//! - Ability to define exceptions
//!
//! ## Usage
//!
//! First add it to your `Cargo.toml` (at the moment using git version, because it was made mainly
//! for [Plume](https://github.com/Plume-org/Plume) and I didn't have the time to backport it to
//! older Rocket version)
//!
//! ```toml
//! [dependencies.rocket_csrf]
//! git = "https://github.com/fdb-hiroshima/rocket_csrf"
//! rev = "50947b8715ae1fa7b73e60b65fdbd1aaf7754f10"
//! ```
//! Then, in your `main.rs`:
//!
//!  ```rust,no_run
//! # extern crate rocket;
//! # extern crate rocket_csrf;
//! use rocket_csrf::CsrfFairingBuilder;
//! # use rocket::Rocket;
//!
//! fn main() {
//!     rocket::ignite()
//!         .attach(rocket_csrf::CsrfFairingBuilder::new()
//!                 //configure it here
//!                 .finalize().unwrap())
//!         //add your routes, other fairings...
//!         .launch();
//! }
//! ```
//!
//! You should define a route for csrf violation error, and registe it in the builder, otherwise
//! errors will simply be redirected to the route matching `/`
//!
extern crate csrf;
extern crate data_encoding;
extern crate rand;
extern crate rocket;
extern crate serde;
extern crate time;

mod csrf_fairing;
mod csrf_proxy;
mod csrf_token;
mod path;
mod utils;

pub use self::csrf_fairing::{CsrfFairing, CsrfFairingBuilder};
pub use self::csrf_token::CsrfToken;
