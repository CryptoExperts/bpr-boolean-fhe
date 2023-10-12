//! Module with the engine definitions.
//!
//! Engines are required to abstract cryptographic notions and efficiently manage memory from the
//! underlying `core_crypto` module.

use crate::gadget::ciphertext::Ciphertext;
use crate::gadget::parameters::BooleanParameters;
use crate::gadget::ClientKey;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use std::cell::RefCell;
pub mod bootstrapping;
use crate::gadget::engine::bootstrapping::{Bootstrapper, ServerKey};
use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, Seeder};
//use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::seeders::new_seeder;

use super::ciphertext::Encoding;

pub(crate) trait BinaryGatesEngine<L, R, K> {
    fn and(&mut self, ct_left: L, ct_right: R, server_key: &K) -> Ciphertext;
    fn nand(&mut self, ct_left: L, ct_right: R, server_key: &K) -> Ciphertext;
    fn nor(&mut self, ct_left: L, ct_right: R, server_key: &K) -> Ciphertext;
    fn or(&mut self, ct_left: L, ct_right: R, server_key: &K) -> Ciphertext;
    fn xor(&mut self, ct_left: L, ct_right: R, server_key: &K) -> Ciphertext;
    fn xnor(&mut self, ct_left: L, ct_right: R, server_key: &K) -> Ciphertext;
}

pub(crate) trait BinaryGatesAssignEngine<L, R, K> {
    fn and_assign(&mut self, ct_left: L, ct_right: R, server_key: &K);
    fn nand_assign(&mut self, ct_left: L, ct_right: R, server_key: &K);
    fn nor_assign(&mut self, ct_left: L, ct_right: R, server_key: &K);
    fn or_assign(&mut self, ct_left: L, ct_right: R, server_key: &K);
    fn xor_assign(&mut self, ct_left: L, ct_right: R, server_key: &K);
    fn xnor_assign(&mut self, ct_left: L, ct_right: R, server_key: &K);
}

/// Trait to be able to acces thread_local
/// engines in a generic way
pub(crate) trait WithThreadLocalEngine {
    fn with_thread_local_mut<R, F>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R;
}

// All our thread local engines
// that our exposed types will use internally to implement their methods
thread_local! {
    static BOOLEAN_ENGINE: RefCell<BooleanEngine> = RefCell::new(BooleanEngine::new());
}

pub struct BooleanEngine {
    /// A structure containing a single CSPRNG to generate secret key coefficients.
    secret_generator: SecretRandomGenerator<ActivatedRandomGenerator>,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    bootstrapper: Bootstrapper,
}

impl WithThreadLocalEngine for BooleanEngine {
    fn with_thread_local_mut<R, F>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        BOOLEAN_ENGINE.with(|engine_cell| func(&mut engine_cell.borrow_mut()))
    }
}


impl BooleanEngine {
    pub fn create_client_key(&mut self, parameters: BooleanParameters) -> ClientKey {
        // generate the lwe secret key
        let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            parameters.lwe_dimension,
            &mut self.secret_generator,
        );

        // generate the glwe secret key
        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            parameters.glwe_dimension,
            parameters.polynomial_size,
            &mut self.secret_generator,
        );

        ClientKey {
            lwe_secret_key,
            glwe_secret_key,
            parameters,
        }
    }

    pub fn create_server_key(&mut self, cks: &ClientKey) -> ServerKey {
        let server_key = self.bootstrapper.new_server_key(cks).unwrap();

        server_key
    }


    pub fn trivial_encrypt(&mut self, message: bool) -> Ciphertext {
        Ciphertext::Trivial(message)
    }

    pub fn encrypt(&mut self, message: bool, encoding : &Encoding, cks: &ClientKey) -> Ciphertext {
        let (new_false, new_true) = encoding.get_values_if_canonical();
        
        // encode the boolean message
        let plain: Plaintext<u32> = if message {
            let buffer : u64 = (1 << 32) / encoding.get_modulus() as u64 * new_true as u64;
            Plaintext(buffer as u32)
        } else {
            let buffer : u64 = (1 << 32) / encoding.get_modulus() as u64 * new_false as u64;

            Plaintext(buffer as u32)
        };


        // encryption
        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            &cks.lwe_secret_key,
            plain,
            cks.parameters.lwe_modular_std_dev,
            &mut self.encryption_generator,
        );

        Ciphertext::Encrypted(ct)
    }


    pub fn decrypt(&mut self, ct: &Ciphertext, encoding : &Encoding, cks: &ClientKey) -> bool {
        match ct {
            Ciphertext::Trivial(b) => *b,
            Ciphertext::Encrypted(ciphertext) => {
                // decryption
                let decrypted = decrypt_lwe_ciphertext(&cks.lwe_secret_key, ciphertext);

                // cast as a u64
                let decrypted_u64 = decrypted.0 as u64;
                //println!("Debug : decrypted : {:#034b}", decrypted_u32);

                
                let divisor : u64 = 1 << 32;
                let divisor_float = divisor as f64;
                let slice : f64 = encoding.get_modulus() as f64 / divisor_float;
                // println!("Debug : decrypted : {}, on Zp : {}", decrypted_u64, decrypted_u64 as f64 / divisor_float * encoding.get_modulus() as f64);

                let closest_integer = (decrypted_u64 as f64 * slice).round() as u32 % encoding.get_modulus();
                //println!("Debug : closest integer : {}", closest_integer);
                // return
                if encoding.is_partition_containing(true, closest_integer) { true }
                else if encoding.is_partition_containing(false, closest_integer) { false }
                else{ panic!("Decryption failed : la valeur obtenue n'est dans les partitions booléenes de l'encodage")}
            }
        }
    }

    pub fn not(&mut self, ct: &Ciphertext) -> Ciphertext {
        match ct {
            Ciphertext::Trivial(message) => Ciphertext::Trivial(!*message),
            Ciphertext::Encrypted(ct_ct) => {
                // Compute the linear combination for NOT: -ct
                let mut ct_res = ct_ct.clone();
                lwe_ciphertext_opposite_assign(&mut ct_res);

                // Output the result:
                Ciphertext::Encrypted(ct_res)
            }
        }
    }

    pub fn not_assign(&mut self, ct: &mut Ciphertext) {
        match ct {
            Ciphertext::Trivial(message) => *message = !*message,
            Ciphertext::Encrypted(ct_ct) => {
                lwe_ciphertext_opposite_assign(ct_ct); // compute the negation
            }
        }
    }
}


////// C'est ici que ça se passe !
/// 

impl BooleanEngine{
    pub fn exec_gadget_with_extraction(&mut self, enc_in : &Vec<Encoding>, enc_inter : &Encoding, enc_out : &Encoding, input : &Vec<Ciphertext>, server_key : &ServerKey) -> Ciphertext{
        let mut buffer_lwe_before_pbs = LweCiphertext::new(
            0u32,
            server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        );

        let bootstrapper = &mut self.bootstrapper;

        // compute the sum
        input.iter().enumerate().for_each(|(i, x)| {
            match x {
                Ciphertext::Encrypted(x_ct) => {
                    lwe_ciphertext_add_assign(&mut buffer_lwe_before_pbs, &x_ct);
                }
                Ciphertext::Trivial(x_bool) => {
                    let plaintext : u64 = (((enc_in[i].get_mono_encoding(*x_bool) as u64) << 32) / enc_in[i].get_modulus() as u64).into();
                    lwe_ciphertext_plaintext_add_assign(&mut buffer_lwe_before_pbs, Plaintext(plaintext as u32));
                }
            }
        });

        // compute the bootstrap and the key switch
        bootstrapper
            .bootstrap_keyswitch(buffer_lwe_before_pbs, enc_inter, enc_out, server_key)
            .unwrap()
    }



    pub fn cast_encoding(&mut self, input : &Ciphertext, coefficient : u32, server_key : &ServerKey) -> Ciphertext{
        let mut result = LweCiphertext::new(
            0u32,
            server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        );
        // compute the product with the coefficient
        let c = Cleartext(coefficient);
        match input {
            Ciphertext::Encrypted(x_ct) => {
                lwe_ciphertext_cleartext_mul(&mut result, &x_ct, c);
                Ciphertext::Encrypted(result)
            }
            Ciphertext::Trivial(_) => {
                panic!("Error : casting a trivial ciphertext ! ");
            }
        }
    }



    pub fn simple_sum(&mut self, input : &Vec<Ciphertext>, server_key : &ServerKey) -> Ciphertext{
        let mut result = LweCiphertext::new(
            0u32,
            server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        );
        input.iter().for_each(|x| 
            match x{
                Ciphertext::Encrypted(x_ct) => {
                    lwe_ciphertext_add_assign(&mut result, x_ct);
                }
                Ciphertext::Trivial(_) => {
                    panic!("simple_sum not yet implemented with plaintexts")
                }
            }
        );
        Ciphertext::Encrypted(result)
    }


    pub fn simple_plaintext_sum(&mut self, input : &Ciphertext, constant : u32, modulus : u32, server_key : &ServerKey) -> Ciphertext{
        let mut result = LweCiphertext::new(
            0u32,
            server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        );        
        let buffer_value : u64 = (1 << 32) / modulus as u64 * constant as u64;
        let value = Plaintext(buffer_value as u32);
        match input{
            Ciphertext::Encrypted(x_ct) => {
                lwe_ciphertext_plaintext_add_assign(&mut result, value);
                lwe_ciphertext_add_assign(&mut result, x_ct);
            }
            Ciphertext::Trivial(_) => {
                panic!("don't use trivial encryption in this context")
            }
        }
        Ciphertext::Encrypted(result)
    }

}

//////////

impl Default for BooleanEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BooleanEngine {
    pub fn new() -> Self {
        let mut root_seeder = new_seeder();

        Self::new_from_seeder(root_seeder.as_mut())
    }

    pub fn new_from_seeder(root_seeder: &mut dyn Seeder) -> Self {
        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(root_seeder.seed());

        // Note that the operands are evaluated from left to right for Rust Struct expressions
        // See: https://doc.rust-lang.org/stable/reference/expressions.html?highlight=left#evaluation-order-of-operands
        Self {
            secret_generator: SecretRandomGenerator::<_>::new(deterministic_seeder.seed()),
            encryption_generator: EncryptionRandomGenerator::<_>::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            bootstrapper: Bootstrapper::new(&mut deterministic_seeder),
        }
    }

    // /// convert into an actual LWE ciphertext even when trivial
    // fn convert_into_lwe_ciphertext_32(
    //     &mut self,
    //     ct: &Ciphertext,
    //     server_key: &ServerKey,
    // ) -> LweCiphertextOwned<u32> {
    //     match ct {
    //         Ciphertext::Encrypted(ct_ct) => ct_ct.clone(),
    //         Ciphertext::Trivial(message) => {
    //             // encode the boolean message
    //             let plain: Plaintext<u32> = if *message {
    //                 Plaintext(PLAINTEXT_TRUE)
    //             } else {
    //                 Plaintext(PLAINTEXT_FALSE)
    //             };
    //             allocate_and_trivially_encrypt_new_lwe_ciphertext(
    //                 server_key
    //                     .bootstrapping_key
    //                     .input_lwe_dimension()
    //                     .to_lwe_size(),
    //                 plain,
    //             )
    //         }
    //     }
    // }
}

