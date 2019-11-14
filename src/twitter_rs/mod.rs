extern crate reqwest;
extern crate base64;
extern crate crypto;
extern crate rand;
extern crate serde_json;
extern crate time;
extern crate url;

use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use rand::Rng;
use rand::distributions::Alphanumeric;
use url::form_urlencoded;

use std::collections::{BTreeMap, HashMap};

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

    pub fn new_with_oauth(_ck: impl Into<String>, _cs: impl Into<String>) {
        let ctx = ClientContext::new(_ck, _cs, "", "");
        let mut param = BTreeMap::<&str, &str>::new();
        param.insert("oauth_callback", "oob");
        let (headers, body) = ctx.build_oauth_request("POST", REQUEST_TOKEN_URL, param);

        for (k, v) in &headers {
            println!("{}: {}", k, v);
        }

        let http_client = reqwest::blocking::Client::new();
        let res = http_client.post(REQUEST_TOKEN_URL)
                             .form(&headers)
                             .body(body)
                             .send()
                             .unwrap();

        println!("{}", &res.status());
        println!("{}", &res.text().unwrap());
    }

    pub fn new_with_xauth(&mut self, username: impl Into<String>, password: impl Into<String>) -> (&str, &str) {
        println!("{}", "hello");
        let a = "";
        let b = "";
        return (a, b);
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

        let encoded_params_strs = params.iter()
                                        .map(|(key, value)| format!("{}={}", key, encode(value)))
                                        .collect::<Vec<String>>()
                                        .join("&");

        let oauth_signature = {
            let signature_param = format!("{}&{}&{}", encode(method.to_uppercase().as_str()), encode(&url), encode(&encoded_params_strs));
            let key = format!("{}&{}", encode(&oauth_consumer_secret), encode(&self.access_token_secret));
            let mut hmac = Hmac::new(Sha1::new(), key.as_bytes());
            hmac.input(signature_param.as_bytes());
            base64::encode(hmac.result().code())
        };

        params.insert("oauth_signature", &oauth_signature);

        let authorization = format!("OAuth {}", params.iter()
                                                      .filter(|&(key, _)| key.starts_with("oauth_"))
                                                      .map(|(key, value)| format!("{}=\"{}\"", key, encode(value)))
                                                      .collect::<Vec<String>>()
                                                      .join(", "));

        // FUCKING EMPTY STRING, WTF, WHY
        //let body = params.iter()
        //                 .filter(|&(k, _)| !k.starts_with("oauth_"))
        //                 .map(|(k, v)| format!("{}={}", k, encode(v)))
        //                 .collect::<Vec<String>>()
        //                 .join("&");

        let encoded_params_strs = params.iter()
                                        .map(|(key, value)| format!("{}={}", key, encode(value)))
                                        .collect::<Vec<String>>()
                                        .join("&");

        println!("{:?}", encoded_params_strs);

        let mut headers = Vec::new();
        headers.push(("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()));
        headers.push(("Authorization".to_string(), authorization));

        return (headers, encoded_params_strs);
    }
}

pub fn generate_nonce() -> String {
    rand::thread_rng().sample_iter(Alphanumeric).take(32).collect::<String>()
}

pub fn encode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()
}
