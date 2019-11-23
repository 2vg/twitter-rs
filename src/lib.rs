extern crate base64;
extern crate crypto;
extern crate rand;
extern crate serde_json;
extern crate time;
extern crate ureq;
extern crate url;

use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use rand::Rng;
use rand::distributions::Alphanumeric;
use url::form_urlencoded;

use std::collections::{BTreeMap, HashMap};

const AUTHORIZE_URL: &'static str = "https://api.twitter.com/oauth/authorize?force_login=1&oauth_token=";
const REQUEST_TOKEN_URL: &'static str = "https://api.twitter.com/oauth/request_token";

pub const ANDROID_CK: &'static str = "3nVuSoBZnx6U4vzUxf5w";
pub const ANDROID_CS: &'static str = "Bcs59EFbbsdF6Sl9Ng71smgStWEGwXXKSjYvPVt7qys";

pub const IPHONE_CK: &'static str = "IQKbtAYlXLripLGPWd0HUA";
pub const IPHONE_CS: &'static str = "GgDYlkSvaPxGxC4X8liwpUoqKwwr3lCADbz8A7ADU";

pub const IPAD_CK: &'static str = "CjulERsDeqhhjSme66ECg";
pub const IPAD_CS: &'static str = "IQWdVyqFxghAtURHGeGiWAsmCAGmdW3WmbEx6Hck";

pub struct ClientContext {
    consumer_key: String,
    consumer_secret: String,
    access_token: String,
    access_token_secret: String,
}

impl ClientContext {
    pub fn new(_ck: impl Into<String>, _cs: impl Into<String>, _at: impl Into<String>, _as: impl Into<String>) -> ClientContext {
        return ClientContext{
            consumer_key: _ck.into(),
            consumer_secret: _cs.into(),
            access_token: _at.into(),
            access_token_secret: _as.into()
        };
    }

    pub fn new_with_oauth_scarping(_ck: impl Into<String>, _cs: impl Into<String>, username: impl Into<String>, password: impl Into<String>) -> Result<ClientContext, String> {
        let mut ctx = ClientContext::new(_ck, _cs, "", "");
        let request_url = ctx.get_request_url();

        println!("{}", &request_url);

        

        Ok(ctx)
    }

    pub fn new_with_xauth(&mut self, username: impl Into<String>, password: impl Into<String>) -> (&str, &str) {
        println!("{}", "hello");
        let a = "";
        let b = "";
        return (a, b);
    }

    pub fn get_request_url(&mut self) -> String {
        let mut param = BTreeMap::<&str, &str>::new();
        param.insert("oauth_callback", "oob");
        let (headers, _) = self.build_oauth_request("POST", REQUEST_TOKEN_URL, param);

        let body = post_request(REQUEST_TOKEN_URL, Some(headers), "");

        match body {
            Ok(body) => {
                let (token, secret) = parse_oauth_token(&body);
                self.access_token = token.to_string();
                self.access_token_secret = secret.to_string();
                format!("{}{}", AUTHORIZE_URL, token)
            },
            Err(msg) => { msg }
        }
    }

    pub fn get_pincode(&self, url: &str, username: &str, password: &str) -> String {
        let res = ureq::get(&url)
                    .timeout_read(1_000)
                    .timeout_connect(1_000)
                    .call();
        let session_cookie = res.header("Set-Cookie").unwrap().to_string();
        let html = res.into_string().unwrap();
        let authenticity_token = authenticity_token_scraping(&html);
        let headers = vec![("Cookie".to_string(), session_cookie),
                           ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())];

        println!("{}", &html);
        let mut params = BTreeMap::<&str, &str>::new();
        params.insert("authenticity_token", &authenticity_token);
        params.insert("oauth_token", &self.access_token);
        params.insert("redirect_after_login", &url);
        params.insert("session[username_or_email]", username);
        params.insert("session[password]", password);

        let body = format_map_with_encode(&params, "", "&", false);
        println!("{}", &body);
        let res = post_request("https://api.twitter.com/oauth/authorize", Some(headers), body);

        println!("{}", res.unwrap());
        "".to_string()
    }

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

        for (key, value) in append_params {
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

fn generate_nonce() -> String {
    rand::thread_rng().sample_iter(Alphanumeric).take(32).collect::<String>()
}

fn encode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()
}

