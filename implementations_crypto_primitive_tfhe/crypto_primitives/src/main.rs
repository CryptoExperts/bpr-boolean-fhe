use std::time::Instant;

use tfhe::{gadget::prelude::*, boolean::{client_key, server_key}};

use aes::{demo_aes, test_parameters_for_aes};
use ascon::demo_ascon;
use sha3::demo_sha3;
use simon::demo_simon;


pub mod symmetric;
pub mod sha3;
pub mod simon;
pub mod ascon;
pub mod utils;
pub mod aes;



fn main(){
    demo_simon();
    
    demo_ascon();
    
    demo_sha3();

    demo_aes();

}









