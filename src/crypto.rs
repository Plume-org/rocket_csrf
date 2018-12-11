use ring::aead::{CHACHA20_POLY1305, OpeningKey, open_in_place, SealingKey, seal_in_place};
use ring::rand::{SecureRandom, SystemRandom};
use std::time::SystemTime;

pub struct CsrfProtection {
    aead_key: [u8; 32],// 256b
}

impl CsrfProtection {
    pub fn from_key(aead_key: [u8; 32]) -> Self {
        CsrfProtection { aead_key }
    }

    pub fn parse_cookie<'a>(&self, cookie: &'a mut [u8]) -> Result<CsrfCookie<'a>, CsrfError> {
        let key = OpeningKey::new(&CHACHA20_POLY1305, &self.aead_key).map_err(|_| CsrfError::UnknownError)?;
        if cookie.len() < 12 {
            return Err(CsrfError::ValidationError);// cookie is too short to be valid
        }
        let (nonce, token) = cookie.split_at_mut(12);// 96b
        let token = open_in_place(&key, nonce, &[], 0, token).map_err(|_| CsrfError::ValidationError)?;
        if token.len() < 8 {// shorter than a timestamp, must be invalid
            return Err(CsrfError::ValidationError);
        }
        let mut expires = [0;8];
        expires.copy_from_slice(&token[..8]);
        let expires = u64::from_be_bytes(expires);
        let token = &token[8..];
        Ok(CsrfCookie{
            token,
            expires,
        })
    }

    pub fn parse_token<'a>(&self, token: &'a mut [u8]) -> Result<CsrfToken<'a>, CsrfError> {
        let key = OpeningKey::new(&CHACHA20_POLY1305, &self.aead_key).map_err(|_| CsrfError::UnknownError)?;
        if token.len() < 12 {
            return Err(CsrfError::ValidationError);// cookie is too short to be valid
        }
        let (nonce, token) = token.split_at_mut(12);// 96b
        let token = open_in_place(&key, nonce, &[], 0, token).map_err(|_| CsrfError::ValidationError)?;
        Ok(CsrfToken{
            token,
        })
    }

    pub fn verify_token_pair(&self, token: CsrfToken, cookie: CsrfCookie) -> bool {
        let token_ok = &token.token == &cookie.token;
        let not_expired = cookie.time_left() > 0; 

        token_ok && not_expired
    }

    pub fn generate_token_pair<'a>(&self, previous_token: Option<CsrfCookie>, ttl_seconds: u64, source_buffer: &'a mut[u8; 64*2+16*2+12*2+8]) -> Result<(&'a[u8], &'a[u8]), CsrfError> {
        let key = SealingKey::new(&CHACHA20_POLY1305, &self.aead_key).map_err(|_| CsrfError::UnknownError)?;
        let (token, cookie) = source_buffer.split_at_mut(64+16+12);
        let expire = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs() + ttl_seconds).map_err(|_| CsrfError::UnknownError)?;
        cookie[12..8+12].copy_from_slice(&expire.to_be_bytes());
        
        let rand = SystemRandom::new();
        if let Some(previous_token) = previous_token {
            cookie[20..64+20].copy_from_slice(previous_token.token);
            token[12..64+12].copy_from_slice(previous_token.token);
        } else {
            rand.fill(&mut token[12..64+12]).map_err(|_| CsrfError::UnknownError)?;
            cookie[20..64+20].copy_from_slice(&token[12..64+12]);
        }
        
        let mut nonce = [0;12];
        
        rand.fill(&mut nonce).map_err(|_| CsrfError::UnknownError)?;
        token[..12].copy_from_slice(&nonce);
        seal_in_place(&key, &nonce, &[], &mut token[12..], CHACHA20_POLY1305.tag_len()).map_err(|_| CsrfError::UnknownError)?;
        rand.fill(&mut nonce).map_err(|_| CsrfError::UnknownError)?;
        cookie[..12].copy_from_slice(&nonce);
        seal_in_place(&key, &nonce, &[], &mut cookie[12..], CHACHA20_POLY1305.tag_len()).map_err(|_| CsrfError::UnknownError)?;

        return Ok((token, cookie));
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
