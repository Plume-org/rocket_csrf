#![deny(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", deny(warnings))]
#![feature(decl_macro, test, proc_macro_hygiene)]
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
extern crate data_encoding;
extern crate ring;
extern crate serde;
extern crate test;
extern crate time;
#[cfg(not(test))]
extern crate rocket;
#[cfg(test)]
#[macro_use]
extern crate rocket;

mod csrf_fairing;
mod csrf_proxy;
mod csrf_token;
mod path;
mod utils;
mod crypto;

pub use self::csrf_fairing::{CsrfFairing, CsrfFairingBuilder};
pub use self::csrf_token::CsrfToken;
const CSRF_COOKIE_NAME: &str = "csrf";
const CSRF_FORM_FIELD: &str = "csrf-token";
const CSRF_FORM_FIELD_MULTIPART: &[u8] = b"Content-Disposition: form-data; name=\"csrf-token\"";


#[cfg(test)]
mod tests {
    use super::*;
    use rocket::{http::Cookie, local::Client};
    use test::Bencher;

    #[bench]
    fn bench_plain_rocket(b: &mut Bencher) {
        let rocket = ::rocket::ignite().mount("/", routes![index, no_modify]);
        let client = Client::new(rocket).expect("valid rocket instance");

        b.iter(|| {
            for _ in 0..100 {
                let _response = client
                    .get("/")
                    .cookie(Cookie::new("some", "cookie"))
                    .dispatch();
            }
        });
    }

    #[bench]
    fn bench_modified_response(b: &mut Bencher) {
        let rocket = ::rocket::ignite()
            .mount("/", routes![index, no_modify])
            .attach(CsrfFairingBuilder::new().finalize().unwrap());
        let client = Client::new(rocket).expect("valid rocket instance");

        b.iter(|| {
            for _ in 0..100 {
                let _response = client
                    .get("/")
                    .cookie(Cookie::new("some", "cookie"))
                    .dispatch();
            }
        });
    }

    #[bench]
    fn bench_unmodified_response(b: &mut Bencher) {
        let rocket = ::rocket::ignite()
            .mount("/", routes![index, no_modify])
            .attach(CsrfFairingBuilder::new().finalize().unwrap());
        let client = Client::new(rocket).expect("valid rocket instance");

        b.iter(|| {
            for _ in 0..100 {
                let _response = client
                    .get("/no-modify")
                    .cookie(Cookie::new("some", "cookie"))
                    .dispatch();
            }
        });
    }

    #[get("/")]
    fn index() -> ::rocket::response::content::Content<&'static str> {
        ::rocket::response::content::Content(
            ::rocket::http::ContentType::HTML,
            "<!DOCTYPE html>
<html>
    <head>
        <meta charset=\"UTF-8\">
        <title>Title of the document</title>
    </head>

    <body>
        Content of the document......
        <form></form>
    </body>
</html>",
        )
    }

    #[get("/no-modify")]
    fn no_modify() -> ::rocket::response::content::Content<&'static str> {
        ::rocket::response::content::Content(
            ::rocket::http::ContentType::HTML,
            "<!DOCTYPE html>
<html>
    <head>
        <meta charset=\"UTF-8\">
        <title>Title of the document</title>
    </head>

    <body>
        Content of the document......
        <span></span>
    </body>
</html>",
        )
    }
}
