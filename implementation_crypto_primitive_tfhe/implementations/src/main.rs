use std::time::Instant;

use tfhe::gadget::prelude::*;

use aes::demo_aes;
use ascon::demo_ascon;
use sha3::demo_sha3;
use simon::demo_simon;

// use simon::State;

pub mod symmetric;
pub mod sha3;
pub mod simon;
pub mod ascon;
pub mod utils;
pub mod aes;


fn main(){
    
    //demo_simon();

    //demo_sha3();

    
    // demo_ascon();
    

    demo_aes();
}






