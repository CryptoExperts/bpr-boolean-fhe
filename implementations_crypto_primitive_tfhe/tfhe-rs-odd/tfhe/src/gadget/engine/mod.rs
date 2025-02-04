//! Module with the engine definitions.
//!
//! Engines are required to abstract cryptographic notions and efficiently manage memory from the
//! underlying `core_crypto` module.

use crate::core_crypto::prelude::EncryptionKeyChoice;
use crate::core_crypto::prelude::CiphertextModulus;
use crate::core_crypto::prelude::PBSOrder;
use crate::gadget::prelude::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use std::arch::x86_64::CpuidResult;
use std::cell::RefCell;
pub mod bootstrapping;
use crate::gadget::engine::bootstrapping::{Bootstrapper, ServerKey};
use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, Seeder};
//use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::seeders::new_seeder;

use super::ciphertext;
use super::ciphertext::ArithmeticEncoding;
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
        let server_key = self.bootstrapper.new_server_key(cks);

        server_key
    }


    pub fn trivial_encrypt(&mut self, message: bool) -> Ciphertext {
        Ciphertext::Trivial(message)
    }


    //common part of Boolean/Arithmetic Encryption
    fn encryption_from_plaintext(&mut self, cks : &ClientKey, plaintext : Plaintext<u32>) -> LweCiphertext<Vec<u32>>{
        let (lwe_sk, encryption_noise) = match cks.parameters.encryption_key_choice {
            EncryptionKeyChoice::Big => (
                cks.glwe_secret_key.as_lwe_secret_key(),
                cks.parameters.glwe_modular_std_dev,
            ),
            EncryptionKeyChoice::Small => {
                let view = LweSecretKey::from_container(cks.lwe_secret_key.as_ref());
                (view, cks.parameters.lwe_modular_std_dev)
            }
        };

        allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            plaintext,
            encryption_noise,
            CiphertextModulus::new_native(),
            &mut self.encryption_generator,
        )
    }



    pub fn encrypt_boolean(&mut self, message: bool, encoding : &BooleanEncoding, cks: &ClientKey) -> Ciphertext {
        let (new_false, new_true) = encoding.get_values_if_canonical();
        
        // encode the boolean message
        let buffer : u64 = if message {
            (1 << 32) / encoding.get_modulus() as u64 * new_true as u64
        } else {
            (1 << 32) / encoding.get_modulus() as u64 * new_false as u64
        };
        let plain =  Plaintext(buffer as u32);
        let ct = self.encryption_from_plaintext(cks, plain);
        Ciphertext::BooleanEncrypted(ct, encoding.clone())
    }


    pub fn encrypt_arithmetic(&mut self, message : u32, encoding : &ArithmeticEncoding, cks : &ClientKey) -> Ciphertext{
        assert!(message < encoding.get_origin_modulus());

        //  Encode the arithmetic message over Zp
        let zpelem = encoding.get_part_single_value_if_canonical(message);
        let buffer : u64 = (1 << 32) / encoding.get_modulus() as u64 * zpelem as u64;
        let plain = Plaintext(buffer as u32);

        let ct = self.encryption_from_plaintext(cks, plain);
        Ciphertext::ArithmeticEncrypted(ct, encoding.clone())
    }


    pub fn decrypt(&mut self, ct: &Ciphertext, cks: &ClientKey) -> u32 {
        let lwe_sk = match cks.parameters.encryption_key_choice {
            EncryptionKeyChoice::Big => cks.glwe_secret_key.as_lwe_secret_key(),
            EncryptionKeyChoice::Small => {
                LweSecretKey::from_container(cks.lwe_secret_key.as_ref())
            }
        };
        match ct {
            Ciphertext::Trivial(b) => if *b {1} else {0},
            Ciphertext::BooleanEncrypted(ciphertext, encoding) => Self::decrypt_boolean(&lwe_sk, ciphertext, encoding),
            Ciphertext::ArithmeticEncrypted(ciphertext, encoding) => Self::decrypt_arithmetic(&lwe_sk, ciphertext, encoding)
        }
    }



    fn decrypt_boolean(lwe_sk : &LweSecretKey<&[u32]>, ciphertext : &LweCiphertext<Vec<u32>>, encoding : &BooleanEncoding) -> u32{
        // decryption
        let decrypted = decrypt_lwe_ciphertext(&lwe_sk, ciphertext);

        // cast as a u64
        let decrypted_u64 = decrypted.0 as u64;
        //println!("Debug : decrypted : {:#034b}", decrypted_u32);

        let divisor : u64 = 1 << 32;
        let divisor_float = divisor as f64;
        let slice : f64 = encoding.get_modulus() as f64 / divisor_float;
        // println!("Debug : decrypted : {}, on Zp : {}", decrypted_u64, decrypted_u64 as f64 / divisor_float * encoding.get_modulus() as f64);

        let closest_integer = (decrypted_u64 as f64 * slice).round() as u32 % encoding.get_modulus();
        
        if encoding.is_partition_containing(true, closest_integer) { 1 }
        else if encoding.is_partition_containing(false, closest_integer) { 0 }
        else{ panic!("Decryption failed : la valeur {} n'est dans les partitions booléenes de l'encodage", closest_integer)}                 
    }


    fn decrypt_arithmetic(lwe_sk : &LweSecretKey<&[u32]>, ciphertext : &LweCiphertext<Vec<u32>>, encoding : &ArithmeticEncoding) -> u32{
        // decryption
        let decrypted = decrypt_lwe_ciphertext(&lwe_sk, ciphertext);

        // cast as a u64
        let decrypted_u64 = decrypted.0 as u64;
        //println!("Debug : decrypted : {:#034b}", decrypted_u32);

        let divisor : u64 = 1 << 32;
        let divisor_float = divisor as f64;
        let slice : f64 = encoding.get_modulus() as f64 / divisor_float;
        // println!("Debug : decrypted : {}, on Zp : {}", decrypted_u64, decrypted_u64 as f64 / divisor_float * encoding.get_modulus() as f64);

        let closest_integer = (decrypted_u64 as f64 * slice).round() as u32 % encoding.get_modulus();
        for i in (0..encoding.get_origin_modulus()){
            if encoding.is_partition_containing(i, closest_integer) {return i;}
        }
        panic!("No value in Zo has been found");
    }
        
        


    pub fn decrypt_float_over_the_torus(&mut self, ct: &Ciphertext, cks: &ClientKey) -> f64 {
        match ct {
            Ciphertext::Trivial(_) => panic!("No error level with trivial ciphertext"),
            Ciphertext::BooleanEncrypted(ciphertext, encoding) => {
                let lwe_sk = match cks.parameters.encryption_key_choice {
                    EncryptionKeyChoice::Big => cks.glwe_secret_key.as_lwe_secret_key(),
                    EncryptionKeyChoice::Small => {
                        LweSecretKey::from_container(cks.lwe_secret_key.as_ref())
                    }
                };
                // decryption
                let decrypted = decrypt_lwe_ciphertext(&lwe_sk, ciphertext);

                // cast as a u64
                let decrypted_u64 = decrypted.0 as u64;
                //println!("Debug : decrypted : {:#034b}", decrypted_u32);

                
                let divisor : u64 = 1 << 32;
                let divisor_float = divisor as f64;
                let slice : f64 = encoding.get_modulus() as f64 / divisor_float;
                // println!("Debug : decrypted : {}, on Zp : {}", decrypted_u64, decrypted_u64 as f64 / divisor_float * encoding.get_modulus() as f64);

                let _closest_integer = (decrypted_u64 as f64 * slice).round() as u32 % encoding.get_modulus();
                // println!("Closest integer : {}", closest_integer);

                decrypted_u64 as f64 / divisor_float
            },
            Ciphertext::ArithmeticEncrypted(_, _) => todo!()
        }
    }

}


////// C'est ici que ça se passe !
/// 

impl BooleanEngine{
    pub fn exec_gadget_with_extraction(&mut self, enc_in : &Vec<BooleanEncoding>, enc_inter : &BooleanEncoding, enc_out : &BooleanEncoding, input : &Vec<Ciphertext>, server_key : &ServerKey) -> Ciphertext{        
        
        let size = match server_key.pbs_order{
            PBSOrder::KeyswitchBootstrap => server_key.key_switching_key.input_key_lwe_dimension().to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key.bootstrapping_key.input_lwe_dimension().to_lwe_size()
        };

        let mut buffer_lwe_before_pbs = LweCiphertext::new(
            0u32,
            size,
            CiphertextModulus::new_native(),
        );

        let bootstrapper = &mut self.bootstrapper;

        // compute the sum
        input.iter().enumerate().for_each(|(i, x)| {
            match x {
                Ciphertext::BooleanEncrypted(x_ct, _) => {
                    lwe_ciphertext_add_assign(&mut buffer_lwe_before_pbs, &x_ct);
                }
                Ciphertext::Trivial(x_bool) => {
                    let plaintext : u64 = (((enc_in[i].get_mono_encoding(*x_bool) as u64) << 32) / enc_in[i].get_modulus() as u64).into();
                    lwe_ciphertext_plaintext_add_assign(&mut buffer_lwe_before_pbs, Plaintext(plaintext as u32));
                }
                Ciphertext::ArithmeticEncrypted(_,_) => panic!("Mixing up Boolean and Arithmetic encodings !")
            }
        });

        // compute the bootstrap and the key switch
        bootstrapper
            .apply_bootstrapping_pattern(buffer_lwe_before_pbs, enc_inter, enc_out, server_key)

    }



    pub fn cast_encoding(&mut self, input : &Ciphertext, coefficient : u32, server_key : &ServerKey) -> Ciphertext{
        
        let size = match server_key.pbs_order{
            PBSOrder::KeyswitchBootstrap => server_key.key_switching_key.input_key_lwe_dimension().to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key.bootstrapping_key.input_lwe_dimension().to_lwe_size()
        };
        let mut result = LweCiphertext::new(
            0u32,
            size,
                CiphertextModulus::new_native(),
        );
        // compute the product with the coefficient
        let c = Cleartext(coefficient);
        match input {
            Ciphertext::BooleanEncrypted(x_ct, encoding) => {
                lwe_ciphertext_cleartext_mul(&mut result, &x_ct, c);
                let new_encoding = encoding.multiply_constant(coefficient);
                Ciphertext::BooleanEncrypted(result, new_encoding)
            }
            Ciphertext::Trivial(_) => {
                panic!("Error : casting a trivial ciphertext ! ");
            }
            Ciphertext::ArithmeticEncrypted(_, _) => todo!()
        }
    }



    pub fn simple_sum(&mut self, input : &Vec<Ciphertext>, server_key : &ServerKey) -> Ciphertext{
        let size = match server_key.pbs_order{
            PBSOrder::KeyswitchBootstrap => server_key.key_switching_key.input_key_lwe_dimension().to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key.bootstrapping_key.input_lwe_dimension().to_lwe_size()
        };
        
        let mut result = LweCiphertext::new(
            0u32,
            size,
            CiphertextModulus::new_native(),
        );
        input.iter().for_each(|x| 
            match x{
                Ciphertext::BooleanEncrypted(x_ct, _) => {
                    lwe_ciphertext_add_assign(&mut result, x_ct);
                }
                Ciphertext::Trivial(_) => {
                    panic!("simple_sum not yet implemented with plaintexts")
                }
                Ciphertext::ArithmeticEncrypted(x_ct, _) => panic!("For now let's say you cannot use the simple sum if the encoding is not the parity encoding")

            }
        );
        Ciphertext::BooleanEncrypted(result, BooleanEncoding::parity_encoding())
    }


    pub fn simple_plaintext_sum(&mut self, input : &Ciphertext, constant : u32, modulus : u32, server_key : &ServerKey) -> Ciphertext{
        
        let size = match server_key.pbs_order{
            PBSOrder::KeyswitchBootstrap => server_key.key_switching_key.input_key_lwe_dimension().to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key.bootstrapping_key.input_lwe_dimension().to_lwe_size()
        };

        let mut result = LweCiphertext::new(
            0u32,
            size,
                CiphertextModulus::new_native(),

        );        
        let buffer_value : u64 = (1 << 32) / modulus as u64 * constant as u64;
        let value = Plaintext(buffer_value as u32);
        match input{
            Ciphertext::BooleanEncrypted(x_ct, encoding) => {
                lwe_ciphertext_plaintext_add_assign(&mut result, value);
                lwe_ciphertext_add_assign(&mut result, x_ct);
                Ciphertext::BooleanEncrypted(result, encoding.clone())
            }
            Ciphertext::Trivial(_) => {
                panic!("don't use trivial encryption in this context")
            }
            Ciphertext::ArithmeticEncrypted(_, _) => panic!("For now let's say you cannot use the simple sum if the encoding is not the parity encoding")
        }
    }


    pub fn simple_plaintext_sum_encoding(&mut self, input : &Ciphertext, constant : u32, modulus : u32, server_key : &ServerKey) -> Ciphertext{
        
        let size = match server_key.pbs_order{
            PBSOrder::KeyswitchBootstrap => server_key.key_switching_key.input_key_lwe_dimension().to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key.bootstrapping_key.input_lwe_dimension().to_lwe_size()
        };

        let mut result = LweCiphertext::new(
            0u32,
            size,
                CiphertextModulus::new_native(),

        );        
        let buffer_value : u64 = (1 << 32) / modulus as u64 * constant as u64;
        let value = Plaintext(buffer_value as u32);
        match input{
            Ciphertext::BooleanEncrypted(x_ct, encoding) => {
                lwe_ciphertext_plaintext_add_assign(&mut result, value);
                lwe_ciphertext_add_assign(&mut result, x_ct);
                Ciphertext::BooleanEncrypted(result, encoding.add_constant(constant))
            }
            Ciphertext::Trivial(_) => {
                panic!("don't use trivial encryption in this context")
            }
            Ciphertext::ArithmeticEncrypted(_, _) => panic!("For now let's say you cannot use the simple sum if the encoding is not the parity encoding")
        }
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

