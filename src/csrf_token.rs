use CSRF_COOKIE_NAME;
use data_encoding::BASE64URL_NOPAD;
use rocket::http::{Cookie, SameSite, Status};
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest};
use rocket::{Request, State};
use serde::{Serialize, Serializer};
use time::Duration;

use crypto::CsrfProtection;

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
            .guard::<State<(CsrfProtection, u64)>>()
            .unwrap()
            .inner();

        let mut cookies = request.cookies();
        if cookies.iter().count() == 0
            || cookies.iter().count() == 1 && cookies.get(CSRF_COOKIE_NAME).is_some()
        {
            Outcome::Forward(())
        } else {
            let mut token_value = cookies
                .get(CSRF_COOKIE_NAME)
                .and_then(|cookie| BASE64URL_NOPAD.decode(cookie.value().as_bytes()).ok());
            let token_value = token_value.as_mut().and_then(|cookie| csrf_engine.parse_cookie(&mut *cookie).ok());

            let mut buf = [0; 192];
            match csrf_engine.generate_token_pair(token_value, *duration, &mut buf) {
                Ok((token, cookie)) => {
                    let mut c =
                        Cookie::build(CSRF_COOKIE_NAME, BASE64URL_NOPAD.encode(cookie))
                            .http_only(true)
                            .secure(true)
                            .same_site(SameSite::Strict)
                            .path("/")
                            .max_age(Duration::seconds(*duration as i64))
                            .finish();

                    cookies.add(c);
                    Outcome::Success(CsrfToken {
                        value: BASE64URL_NOPAD.encode(token),
                    })
                }
                Err(_) => Outcome::Failure((Status::InternalServerError, ())),
            }
        }
    }
}
