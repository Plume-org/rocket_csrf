use csrf::{AesGcmCsrfProtection, CsrfProtection, CSRF_COOKIE_NAME};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use rocket::{Request, State};
use rocket::http::{Cookie, Status};
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest};
use serde::{Serialize, Serializer};
use time::Duration;

/// Csrf token to insert into pages.
///
/// The `CsrfToken` type allow you to add tokens into your pages anywhere you want, and is mainly
/// usefull if you disabled auto-insert when building the fairing registered in Rocket.
/// This impltement Serde's Serialize so you may insert it directly into your templats as if it was
/// a String. It also implement FromRequest so you can get it as a request guard. This is also the
/// only way to get this struct.
#[derive(Debug, Clone)]
pub struct CsrfToken {
    value: String,
}

impl CsrfToken {
    ///Obtain the value of the underlying token
    pub fn value(&self) -> &[u8] {
        self.value.as_bytes()
    }
}

impl Serialize for CsrfToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.value) //simply serialise to the underlying String
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for CsrfToken {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, ()> {
        let (csrf_engine, duration) = request
            .guard::<State<(AesGcmCsrfProtection, i64)>>()
            .unwrap()
            .inner();

        let mut cookies = request.cookies();
        let token_value = cookies
            .get(CSRF_COOKIE_NAME)
            .and_then(|cookie| BASE64.decode(cookie.value().as_bytes()).ok())
            .and_then(|cookie| csrf_engine.parse_cookie(&cookie).ok())
            .and_then(|cookie| {
                let value = cookie.value();
                if value.len() == 64 {
                    let mut array = [0; 64];
                    array.copy_from_slice(&value);
                    Some(array)
                } else {
                    None
                }
            }); //when request guard is called, parse cookie to get it's encrypted secret (if there is a cookie)

        match csrf_engine.generate_token_pair(token_value.as_ref(), *duration) {
            Ok((token, cookie)) => {
                let mut c = Cookie::new(CSRF_COOKIE_NAME, cookie.b64_string());
                c.set_http_only(true);
                c.set_max_age(Duration::seconds(*duration));
                cookies.add(c); //TODO add a same_site and secure to the cookie
                Outcome::Success(CsrfToken {
                    value: BASE64URL_NOPAD.encode(token.value()),
                })
            }
            Err(_) => Outcome::Failure((Status::InternalServerError, ())),
        }
    }
}
