pub mod official;

extern crate base64;
extern crate crypto;
extern crate rand;
extern crate serde_json;
extern crate time;
extern crate ureq;
extern crate url;

use crate::official::*;

use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use rand::Rng;
use rand::distributions::Alphanumeric;
use url::form_urlencoded;

use std::collections::{BTreeMap, HashMap};

const AUTHORIZE_URL: &'static str = "https://api.twitter.com/oauth/authorize?oauth_token=";
const REQUEST_TOKEN_URL: &'static str = "https://api.twitter.com/oauth/request_token";
const REQUEST_ACCESS_TOKEN_URL: &'static str = "https://api.twitter.com/oauth/access_token";

pub const ANDROID_CK: &'static str = "3nVuSoBZnx6U4vzUxf5w";
pub const ANDROID_CS: &'static str = "Bcs59EFbbsdF6Sl9Ng71smgStWEGwXXKSjYvPVt7qys";

pub const IPHONE_CK: &'static str = "IQKbtAYlXLripLGPWd0HUA";
pub const IPHONE_CS: &'static str = "GgDYlkSvaPxGxC4X8liwpUoqKwwr3lCADbz8A7ADU";

pub const IPAD_CK: &'static str = "CjulERsDeqhhjSme66ECg";
pub const IPAD_CS: &'static str = "IQWdVyqFxghAtURHGeGiWAsmCAGmdW3WmbEx6Hck";

pub struct ClientContext {
    pub consumer_key: String,
    pub consumer_secret: String,
    oauth_token: String,
    oauth_access_token: String,
    pub access_token: String,
    pub access_token_secret: String,
}

impl ClientContext {
    pub fn new(_ck: impl Into<String>, _cs: impl Into<String>, _at: impl Into<String>, _as: impl Into<String>) -> ClientContext {
        return ClientContext{
            consumer_key: _ck.into(),
            consumer_secret: _cs.into(),
            oauth_token: "".into(),
            oauth_access_token: "".into(),
            access_token: _at.into(),
            access_token_secret: _as.into()
        };
    }

    /*
    pub fn new_with_oauth_scarping(_ck: impl Into<String>, _cs: impl Into<String>, username: impl Into<String>, password: impl Into<String>) -> Result<ClientContext, String> {
        let mut ctx = ClientContext::new(_ck, _cs, "", "");
        let request_url = ctx.get_request_url();

        println!("{}", &request_url);

        Ok(ctx)
    }
    */

    pub fn new_with_xauth(username: impl Into<String>, password: impl Into<String>, kind: OfficialClient) -> ClientContext {
        let mut ctx = match kind {
            OfficialClient::android => { ClientContext::new(ANDROID_CK, ANDROID_CS, "", "") },
            OfficialClient::iphone => { ClientContext::new(IPHONE_CK, IPHONE_CS, "", "") },
            OfficialClient::ipad => { ClientContext::new(IPAD_CK, IPAD_CS, "", "") },
            OfficialClient::windows => { ClientContext::new(WINDOWS_CK, WINDOWS_CS, "", "") },
            OfficialClient::windows_phone => { ClientContext::new(WINDOWS_PHONE_CK, WINDOWS_PHONE_CS, "", "") },
            OfficialClient::google => { ClientContext::new(GOOGLE_CK, GOOGLE_CS, "", "") },
            OfficialClient::mac => { ClientContext::new(MAC_CK, MAC_CS, "", "") }
        };

        let (username, password) = (username.into(), password.into());

        let mut params = BTreeMap::<&str, &str>::new();
        params.insert("x_auth_mode", "client_auth");
        params.insert("x_auth_username", &username);
        params.insert("x_auth_password", &password);
        let (headers, body) = ctx.build_oauth_request("POST", REQUEST_ACCESS_TOKEN_URL, params);

        println!("{:?}", &headers);
        println!("{:?}", &body);

        let body = post_request(REQUEST_ACCESS_TOKEN_URL, Some(headers), "");
        println!("{:?}", &body);

        match body {
            Ok(body) => {
                let (token, secret) = parse_oauth_token(&body);
                ctx.access_token = token.to_string();
                ctx.access_token_secret = secret.to_string();
            },
            Err(msg) => { println!("{}", msg); }
        }

        return ctx;
    }

    pub fn get_request_url(&mut self) -> String {
        let mut param = BTreeMap::<&str, &str>::new();
        param.insert("oauth_callback", "oob");
        let (headers, _) = self.build_oauth_request("POST", REQUEST_TOKEN_URL, param);

        let body = post_request(REQUEST_TOKEN_URL, Some(headers), "");

        match body {
            Ok(body) => {
                let (token, secret) = parse_oauth_token(&body);
                self.oauth_token = token.to_string();
                self.oauth_access_token = secret.to_string();
                format!("{}{}", AUTHORIZE_URL, token)
            },
            Err(msg) => { msg }
        }
    }

    pub fn get_access_token(&mut self, verifier: impl Into<String>) {
        let verifier = verifier.into();

        let mut params: BTreeMap<&str, &str> = BTreeMap::new();
        params.insert("oauth_token", &self.oauth_token);
        params.insert("oauth_verifier", &verifier);
        let (headers, _) = self.build_oauth_request("POST", REQUEST_ACCESS_TOKEN_URL, params);

        let body = post_request(REQUEST_ACCESS_TOKEN_URL, Some(headers), "");

        match body {
            Ok(body) => {
                let (token, secret) = parse_oauth_token(&body);
                self.access_token = token.to_string();
                self.access_token_secret = secret.to_string();
            },
            Err(msg) => { println!("{}", msg); }
        }
    }

    /*
    pub fn get_pincode(&self, url: &str, username: &str, password: &str) -> String {
        let html = get_request(url, None, None).unwrap();
        let authenticity_token = authenticity_token_scraping(&html);
        let headers = vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())];

        let mut params = BTreeMap::<&str, &str>::new();
        params.insert("authenticity_token", &authenticity_token);
        params.insert("oauth_token", &self.access_token);
        params.insert("redirect_after_login", url);
        params.insert("session%5Busername_or_email%5D", username);
        params.insert("session%5Bpassword%5D", password);

        let body = format_map_with_encode(&params, "", "&", false);
        println!("{}", &url);
        println!("{}", &body);
        //let res = post_request(url, Some(headers), body);
        //println!("{}", res.unwrap());
        "".to_string()
    }
    */

    pub fn build_oauth_request(
        &self,
        method: impl Into<String>,
        url: impl Into<String>,
        append_params: BTreeMap<&str, &str>)
    -> (Vec<(String, String)>, String) {
        let mut params = BTreeMap::<&str, &str>::new();

        let method = method.into();
        let url = url.into();

        let nonce = generate_nonce();
        let time_now = time::now().to_timespec().sec.to_string();
        let oauth_consumer_key = &self.consumer_key;
        let oauth_consumer_secret = &self.consumer_secret;

        params.insert("oauth_consumer_key", &oauth_consumer_key);
        params.insert("oauth_nonce", &nonce);
        params.insert("oauth_signature_method", "HMAC-SHA1");
        params.insert("oauth_timestamp", &time_now);
        params.insert("oauth_version", "1.0");

        for (key, value) in &append_params {
            params.insert(key, value);
        }

        let encoded_params_strs = format_map_with_encode(&params, "", "&", true);

        let oauth_signature = {
            let signature_param = format!("{}&{}&{}", encode(method.to_uppercase().as_str()), encode(&url), encode(&encoded_params_strs));
            let key = format!("{}&{}", encode(&oauth_consumer_secret), encode(&self.access_token_secret));
            let mut hmac = Hmac::new(Sha1::new(), key.as_bytes());
            hmac.input(signature_param.as_bytes());
            base64::encode(hmac.result().code())
        };

        params.insert("oauth_signature", &oauth_signature);

        let authorization = format!("OAuth {}", format_map_with_encode(&params, "\"", ", ", true));

        let body = format_map_with_encode(&params, "", "&", false);

        let mut headers = Vec::new();
        headers.push(("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()));
        headers.push(("Authorization".to_string(), authorization));

        for (k, v) in append_params {
            match k {
                "x_auth_mode" => { headers.push(("x_auth_mode".to_string(), v.to_string())); },
                "x_auth_username" => { headers.push(("x_auth_username".to_string(), v.to_string())); },
                "x_auth_password" => { headers.push(("x_auth_password".to_string(), v.to_string())); },
                _ => {}
            }
        }

        return (headers, body);
    }
}

fn get_request(
    url: impl Into<String>,
    headers: Option<Vec<(String, String)>>,
    querys: Option<Vec<(String, String)>>
) -> Result<String, String> {
    let url = url.into();
    let mut req = ureq::get(&url);

    match headers {
        Some(headers) => {
            for (k, v) in &headers {
                &req.set(k, v);
            }
        },
        None => {}
    }

    match querys {
        Some(querys) => {
            for (k, v) in &querys {
                &req.query(k, v);
            }
        },
        None => {}
    }

    let res = req.timeout_read(1_000)
                 .timeout_connect(1_000)
                 .call()
                 .into_string();
    match res {
        Ok(body) => {
            return Ok(body);
        },
        Err(msg) => { return Err(msg.to_string()); }
    }
}

fn post_request(
    url: impl Into<String>,
    headers: Option<Vec<(String, String)>>,
    body: impl Into<String>
) -> Result<String, String> {
    let url = url.into();
    let body = body.into();
    let mut req = ureq::post(&url);

    match headers {
        Some(headers) => {
            for (k, v) in &headers {
                &req.set(k, v);
            }
        },
        None => {}
    }

    let res = req.timeout_read(1_000)
                 .timeout_connect(1_000)
                 .send_string(&body)
                 .into_string();
    match res {
        Ok(body) => {
            return Ok(body);
        },
        Err(msg) => { return Err(msg.to_string()); }
    }
}

fn format_map_with_encode(map: &BTreeMap<&str, &str>, delimiter: &str, separator: &str, for_oauth: bool) -> String {
    map.iter()
       .filter(|&(k, _)| k.starts_with("oauth_") == for_oauth)
       .map(|(k, v)| format!("{}={}{}{}", k, delimiter, encode(v), delimiter))
       .collect::<Vec<String>>()
       .join(separator)
}

fn parse_oauth_token<'a>(strings: &'a str) -> (&'a str, &'a str) {
    if strings.find("oauth_token") == None { return ("", "") }

    let splits = &strings.split('&')
                         .map(|s| s.split('=').collect::<Vec<&str>>()[1])
                         .collect::<Vec<&str>>();
    (splits[0], splits[1])
}

fn generate_nonce() -> String {
    rand::thread_rng().sample_iter(Alphanumeric).take(32).collect::<String>()
}

fn encode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()
}

/*
fn authenticity_token_scraping(html: &str) -> String {
    let pattern = "<input name=\"authenticity_token\" type=\"hidden\" value=\"";
    let found = html.find(pattern);
    if found == None { return "".to_string(); }

    let pin_idx_first = found.unwrap() + pattern.len();
    let tmp_html = &html[pin_idx_first..];
    let pin_idx_last = pin_idx_first + tmp_html.find("\"").unwrap();
    
    html[pin_idx_first..pin_idx_last].to_string()
}

fn pincode_scraping(html: &str) -> String {
    let pattern = "<code>";
    let found = html.find(pattern);
    if found == None { return "".to_string(); }

    println!("{}", &html);

    let pin_idx_first = found.unwrap() + pattern.len();
    let tmp_html = &html[pin_idx_first..];
    let pin_idx_last = pin_idx_first + tmp_html.find("</code>").unwrap();
    
    html[pin_idx_first..pin_idx_last].to_string()
}
*/
