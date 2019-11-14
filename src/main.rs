extern crate reqwest;
extern crate twitter_rs;

use twitter_rs::*;

fn main() {
    twitter_rs::ClientContext::new_with_oauth(ANDROID_CK, ANDROID_CS);
}
