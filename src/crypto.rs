use ring::aead::{CHACHA20_POLY1305, OpeningKey, SealingKey, UnboundKey, BoundKey, Nonce, NonceSequence, Aad};
use ring::constant_time::verify_slices_are_equal;
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use std::time::SystemTime;


const KEYSIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const DATE_SIZE: usize = 8;
const TAG_SIZE: usize = 64;
const SIG_SIZE: usize = 16;
const TOKEN_SIZE: usize = NONCE_SIZE + TAG_SIZE + SIG_SIZE;
const COOKIE_SIZE: usize = NONCE_SIZE + DATE_SIZE + TAG_SIZE + SIG_SIZE;


pub struct CsrfProtection {
    aead_key: [u8; KEYSIZE],
}

impl CsrfProtection {
    pub fn from_key(aead_key: [u8; KEYSIZE]) -> Self {
        CsrfProtection { aead_key }
    }

    pub fn parse_cookie<'a>(&self, cookie: &'a mut [u8]) -> Result<CsrfCookie<'a>, CsrfError> {
        if cookie.len() < NONCE_SIZE {
            return Err(CsrfError::ValidationError);// cookie is too short to be valid
        }
        let (nonce, token) = cookie.split_at_mut(NONCE_SIZE);
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &self.aead_key).map_err(|_| CsrfError::UnknownError)?;
        let nonce = OneNonceSequence::new(Nonce::try_assume_unique_for_key(nonce).map_err(|_| CsrfError::ValidationError)?);
        let mut key = OpeningKey::new(unbound_key, nonce);
        let token = key.open_in_place(Aad::from(&[]), token).map_err(|_| CsrfError::ValidationError)?;
        if token.len() < DATE_SIZE {// shorter than a timestamp, must be invalid
            return Err(CsrfError::ValidationError);
        }
        let mut expires = [0;DATE_SIZE];
        expires.copy_from_slice(&token[..DATE_SIZE]);
        let expires = u64::from_be_bytes(expires);
        let token = &token[DATE_SIZE..];
        Ok(CsrfCookie{
            token,
            expires,
        })
    }

    pub fn parse_token<'a>(&self, token: &'a mut [u8]) -> Result<CsrfToken<'a>, CsrfError> {
        if token.len() < NONCE_SIZE {
            return Err(CsrfError::ValidationError);// cookie is too short to be valid
        }
        let (nonce, token) = token.split_at_mut(NONCE_SIZE);
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &self.aead_key).map_err(|_| CsrfError::ValidationError)?;
        let nonce = OneNonceSequence::new(Nonce::try_assume_unique_for_key(nonce).map_err(|_| CsrfError::ValidationError)?);
        let mut key = OpeningKey::new(unbound_key, nonce);
        // let token = open_in_place(&key, nonce, &[], 0, token).map_err(|_| CsrfError::ValidationError)?;
        let token = key.open_in_place(Aad::from(&[]), token).map_err(|_| CsrfError::ValidationError)?;
        Ok(CsrfToken{
            token,
        })
    }

    pub fn verify_token_pair(&self, token: &CsrfToken, cookie: &CsrfCookie) -> bool {
        let token_ok = verify_slices_are_equal(token.token,cookie.token).is_ok();
        let not_expired = cookie.time_left() > 0; 

        token_ok && not_expired
    }

    pub fn generate_token_pair<'a>(&self, previous_token: Option<CsrfCookie>, ttl_seconds: u64, source_buffer: &'a mut[u8; TOKEN_SIZE + COOKIE_SIZE]) -> Result<(&'a[u8], &'a[u8]), CsrfError> {
        let (token, cookie) = source_buffer.split_at_mut(TOKEN_SIZE);
        let expire = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs() + ttl_seconds).map_err(|_| CsrfError::UnknownError)?;
        cookie[NONCE_SIZE..DATE_SIZE+NONCE_SIZE].copy_from_slice(&expire.to_be_bytes());
        
        let rand = SystemRandom::new();
        if let Some(previous_token) = previous_token {
            cookie[NONCE_SIZE+DATE_SIZE..TAG_SIZE+NONCE_SIZE+DATE_SIZE].copy_from_slice(previous_token.token);
            token[NONCE_SIZE..TAG_SIZE+NONCE_SIZE].copy_from_slice(previous_token.token);
        } else {
            rand.fill(&mut token[NONCE_SIZE..TAG_SIZE+NONCE_SIZE]).map_err(|_| CsrfError::UnknownError)?;
            cookie[NONCE_SIZE+DATE_SIZE..TAG_SIZE+NONCE_SIZE+DATE_SIZE].copy_from_slice(&token[NONCE_SIZE..TAG_SIZE+NONCE_SIZE]);
        }
        
        let mut nonce = [0;NONCE_SIZE];
        
        rand.fill(&mut nonce).map_err(|_| CsrfError::UnknownError)?;
        self.seal_in_place(nonce, token, TOKEN_SIZE)?;

        rand.fill(&mut nonce).map_err(|_| CsrfError::UnknownError)?;
        self.seal_in_place(nonce, cookie, COOKIE_SIZE)?;

        Ok((token, cookie))
    }

    fn seal_in_place(&self, nonce: [u8; NONCE_SIZE], in_out: &mut [u8], in_out_size: usize) -> Result<(), CsrfError> {
        in_out[..NONCE_SIZE].copy_from_slice(&nonce);
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &self.aead_key).map_err(|_| CsrfError::ValidationError)?;
        let nonce_sequence = OneNonceSequence::new(Nonce::assume_unique_for_key(nonce));
        let mut key = SealingKey::new(unbound_key, nonce_sequence);
        let mut io = Vec::from(&in_out[NONCE_SIZE..(in_out_size - SIG_SIZE)]);
        key.seal_in_place_append_tag(Aad::from(&[]), &mut io).map_err(|_| CsrfError::UnknownError)?;
        in_out[NONCE_SIZE..].copy_from_slice(&io);

        Ok(())
    }
}

pub struct CsrfToken<'a> {
    token: &'a[u8],
}

pub struct CsrfCookie<'a> {
    token: &'a[u8],
    expires: u64
}

impl<'a> CsrfCookie<'a> {
    pub fn time_left(&self) -> u64 {
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).ok().and_then(|now| self.expires.checked_sub(now.as_secs())).unwrap_or(0)
    }
}

pub enum CsrfError {
    ValidationError,
    UnknownError,
}

// from ring's test
struct OneNonceSequence(Option<Nonce>);

impl OneNonceSequence {
    /// Constructs the sequence allowing `advance()` to be called
    /// `allowed_invocations` times.
    fn new(nonce: Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}
