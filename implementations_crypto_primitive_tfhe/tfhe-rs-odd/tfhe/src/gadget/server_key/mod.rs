//! The public key for homomorphic computation.
//!
//! This module implements the generation of the server's public key, together with all the
//! available homomorphic Boolean gates ($\mathrm{AND}$, $\mathrm{MUX}$, $\mathrm{NAND}$,
//! $\mathrm{NOR}$,
//! $\mathrm{NOT}$, $\mathrm{OR}$, $\mathrm{XNOR}$, $\mathrm{XOR}$).

#[cfg(test)]
mod tests;

use crate::{gadget::ciphertext::Ciphertext};
use crate::gadget::client_key::ClientKey;
pub use crate::gadget::engine::bootstrapping::{ServerKey};
use crate::gadget::engine::{
    BooleanEngine, WithThreadLocalEngine,
};

use super::ciphertext::BooleanEncoding;

impl ServerKey {
    //////Boolean only : gadget logic (see paper)//////
    pub fn exec_gadget_with_extraction(&self, enc_in : &Vec<BooleanEncoding>, enc_inter : &BooleanEncoding, enc_out : &BooleanEncoding, input : &Vec<Ciphertext>) -> Ciphertext{
        BooleanEngine::with_thread_local_mut(|engine| engine.exec_gadget_with_extraction(enc_in, enc_inter, enc_out, input, &self))
    }

    /////Encoding Switching : universal
    //transforme un encodage en un autre avec un external product par un coefficient donné
    pub fn cast_encoding(&self, input : &Ciphertext, coefficient : u32) -> Ciphertext{
        BooleanEngine::with_thread_local_mut(|engine| engine.cast_encoding(input, coefficient, &self))
    }

    pub fn simple_plaintext_sum_encoding(&self, input : &Ciphertext, constant : u32, modulus : u32) -> Ciphertext{
        BooleanEngine::with_thread_local_mut(|engine| engine.simple_plaintext_sum_encoding(input, constant, modulus,&self))
    }
    ////////////////////////


    ///Simple Sum : (only boolean for now)
    //simple sum : no check is performed so use it wisely
    pub fn simple_sum(&self, input : &Vec<Ciphertext>) -> Ciphertext{
        BooleanEngine::with_thread_local_mut(|engine| engine.simple_sum(input, &self))
    }

    pub fn simple_plaintext_sum(&self, input : &Ciphertext, constant : u32, modulus : u32) -> Ciphertext{
        BooleanEngine::with_thread_local_mut(|engine| engine.simple_plaintext_sum(input, constant, modulus,&self))
    }


}


impl ServerKey {
    pub fn new(cks: &ClientKey) -> Self {
        BooleanEngine::with_thread_local_mut(|engine| engine.create_server_key(cks))
    }

    pub fn trivial_encrypt(&self, message: bool) -> Ciphertext {
        Ciphertext::Trivial(message)
    }
}

