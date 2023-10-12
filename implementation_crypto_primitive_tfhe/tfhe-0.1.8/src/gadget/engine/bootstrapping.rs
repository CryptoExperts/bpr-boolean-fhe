use crate::gadget::ciphertext::{Ciphertext, Encoding};
use crate::gadget::{ClientKey};
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::generators::{DeterministicSeeder, EncryptionRandomGenerator};
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, Seeder};
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::math::fft::Fft;
use std::error::Error;


/////Accumulator used in the BlindRotate part of the bootstrapping
type Accumulator = Vec<u32>;


/// Memory used as buffer for the bootstrap
///
/// It contains contiguous chunk which is then sliced and converted
/// into core's View types.
#[derive(Default)]
pub struct Memory {
    buffer: Vec<u32>,
}

impl Memory {
    pub fn create_accumulator(encoding_in : &Encoding, encoding_out : &Encoding) -> Accumulator{
        assert!(encoding_in.is_extrayable());
        assert!(encoding_out.is_canonical());
        let p = encoding_in.get_modulus();
        assert!(p % 2 == 1);
        let new_p = encoding_out.get_modulus();
        let mut accu : Accumulator = vec![0;p.try_into().unwrap()];
        let (new_false, new_true) = encoding_out.get_values_if_canonical();
        for k in 0..((p + 1) / 2){
            if encoding_in.is_partition_containing(false, k){
                accu[2 * k as usize] = new_false;
            } 
            else if encoding_in.is_partition_containing(true, k){
                accu[2 * k as usize] = new_true;
            }
            if encoding_in.is_partition_containing(false, (p + 1) / 2 + k){
                accu[(2 * k + 1) as usize] = (new_p - new_false) % new_p;
            }
            else if encoding_in.is_partition_containing(true, (p + 1) / 2 + k){
                accu[(2 * k + 1) as usize] = (new_p - new_true) % new_p;
            }
        }
        accu
    }

    /// Return a tuple with buffers that matches the server key.
    ///
    /// - The first element is the accumulator for bootstrap step.
    /// - The second element is a lwe buffer where the result of the of the bootstrap should be
    ///   written
    fn as_buffers(
        &mut self,
        server_key: &ServerKey,
        enc_in : &Encoding,
        enc_out : &Encoding
    ) -> (GlweCiphertextView<'_, u32>, LweCiphertextMutView<'_, u32>) {
        let num_elem_in_accumulator = server_key.bootstrapping_key.glwe_size().0
            * server_key.bootstrapping_key.polynomial_size().0;
        let num_elem_in_lwe = server_key
            .bootstrapping_key
            .output_lwe_dimension()
            .to_lwe_size()
            .0;
        let total_elem_needed = num_elem_in_accumulator + num_elem_in_lwe;

        let all_elements = if self.buffer.len() < total_elem_needed {
            self.buffer.resize(total_elem_needed, 0u32);
            self.buffer.as_mut_slice()
        } else {
            &mut self.buffer[..total_elem_needed]
        };

        let (accumulator_elements, lwe_elements) =
            all_elements.split_at_mut(num_elem_in_accumulator);

        {
            let mut accumulator = GlweCiphertextMutView::from_container(
                accumulator_elements,
                server_key.bootstrapping_key.polynomial_size(),
            );

            ////accumulator filling
            let p = enc_in.get_modulus();
            let new_p = enc_out.get_modulus() as u64;
            accumulator.get_mut_mask().as_mut().fill(0u32);
            let N_poly: usize = accumulator.get_mut_body().as_mut().len();    //(N degree of the polynomial)

            if p % 2 == 1{
                let accu_data = Self::create_accumulator(enc_in, enc_out);
                let const_shift = N_poly / (2 * p) as usize;   //half a window

                let mut buffer_value : u64 = (1 << 32) / new_p * accu_data[0] as u64;    //value to be written in the accumulator, put in a u64 to enhance the precision of the / operation
                accumulator.get_mut_body().as_mut()[..const_shift].fill(buffer_value as u32);   //filling of the first half window
                for k in 1..accu_data.len(){
                    buffer_value = (1 << 32) / new_p * accu_data[k] as u64;
                    accumulator.get_mut_body().as_mut()[const_shift + (k - 1) * N_poly / p as usize..const_shift + k * N_poly / p as usize].fill(buffer_value as u32); //filling of the (k+1)th window
                }
                buffer_value = (1 << 32) / new_p as u64 * (enc_out.get_modulus() - accu_data[0] % enc_out.get_modulus()) as u64;
                accumulator.get_mut_body().as_mut()[N_poly  - const_shift..].fill(buffer_value as u32);//filling of the last half-window
            }
            else if p == 2{
                //check that we have negacyclicity
                let (new_false, new_true) = enc_out.get_values_if_canonical();
                assert_eq!(new_false, (enc_out.get_modulus() -  new_true) % enc_out.get_modulus());
                //Is the 0 window true or false ?
                let partition_containing_zero = enc_in.is_partition_containing(true, 0);
                //filling of the accu
                let mut buffer_value = (1 << 32) / new_p * enc_out.get_mono_encoding(partition_containing_zero) as u64;
                accumulator.get_mut_body().as_mut()[..N_poly / 2].fill(buffer_value as u32);   //filling of the first half window
                buffer_value = (1 << 32) / new_p * enc_out.get_mono_encoding(!partition_containing_zero) as u64;
                accumulator.get_mut_body().as_mut()[N_poly / 2..].fill(buffer_value as u32);   //filling of the second half window
            }
        }

        let accumulator = GlweCiphertextView::from_container(
            accumulator_elements,
            server_key.bootstrapping_key.polynomial_size(),
        );

        let lwe = LweCiphertextMutView::from_container(lwe_elements);

        (accumulator, lwe)
    }
}

/// A structure containing the server public key.
///
/// This server key data lives on the CPU.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic Boolean circuits.
///
/// In more details, it contains:
/// * `bootstrapping_key` - a public key, used to perform the bootstrapping operation.
/// * `key_switching_key` - a public key, used to perform the key-switching operation.
#[derive(Clone)]
pub struct ServerKey {
    pub(crate) bootstrapping_key: FourierLweBootstrapKeyOwned,
    pub(crate) key_switching_key: LweKeyswitchKeyOwned<u32>,
}

impl ServerKey {
    pub fn bootstrapping_key_size_elements(&self) -> usize {
        self.bootstrapping_key.as_view().data().as_ref().len()
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        self.bootstrapping_key_size_elements() * std::mem::size_of::<concrete_fft::c64>()
    }

    pub fn key_switching_key_size_elements(&self) -> usize {
        self.key_switching_key.as_ref().len()
    }

    pub fn key_switching_key_size_bytes(&self) -> usize {
        self.key_switching_key_size_elements() * std::mem::size_of::<u64>()
    }
}


/// Perform ciphertext bootstraps on the CPU
pub(crate) struct Bootstrapper {
    memory: Memory,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    pub(crate) encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    pub(crate) computation_buffers: ComputationBuffers,
    pub(crate) seeder: DeterministicSeeder<ActivatedRandomGenerator>,
}

impl Bootstrapper {
    pub fn new(seeder: &mut dyn Seeder) -> Self {
        Bootstrapper {
            memory: Default::default(),
            encryption_generator: EncryptionRandomGenerator::<_>::new(seeder.seed(), seeder),
            computation_buffers: Default::default(),
            seeder: DeterministicSeeder::<_>::new(seeder.seed()),
        }
    }

    pub(crate) fn new_server_key(
        &mut self,
        cks: &ClientKey,
    ) -> Result<ServerKey, Box<dyn std::error::Error>> {
        let standard_bootstraping_key: LweBootstrapKeyOwned<u32> =
            par_allocate_and_generate_new_lwe_bootstrap_key(
                &cks.lwe_secret_key,
                &cks.glwe_secret_key,
                cks.parameters.pbs_base_log,
                cks.parameters.pbs_level,
                cks.parameters.glwe_modular_std_dev,
                &mut self.encryption_generator,
            );

        // creation of the bootstrapping key in the Fourier domain
        let mut fourier_bsk = FourierLweBootstrapKey::new(
            standard_bootstraping_key.input_lwe_dimension(),
            standard_bootstraping_key.glwe_size(),
            standard_bootstraping_key.polynomial_size(),
            standard_bootstraping_key.decomposition_base_log(),
            standard_bootstraping_key.decomposition_level_count(),
        );

        let fft = Fft::new(standard_bootstraping_key.polynomial_size());
        let fft = fft.as_view();
        self.computation_buffers.resize(
            convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        // Conversion to fourier domain
        convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized(
            &standard_bootstraping_key,
            &mut fourier_bsk,
            fft,
            stack,
        );

        // Convert the GLWE secret key into an LWE secret key:
        let big_lwe_secret_key = cks.glwe_secret_key.clone().into_lwe_secret_key();

        // creation of the key switching key
        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_secret_key,
            &cks.lwe_secret_key,
            cks.parameters.ks_base_log,
            cks.parameters.ks_level,
            cks.parameters.lwe_modular_std_dev,
            &mut self.encryption_generator,
        );

        Ok(ServerKey {
            bootstrapping_key: fourier_bsk,
            key_switching_key: ksk,
        })
    }


    pub(crate) fn bootstrap_keyswitch(
        &mut self,
        mut ciphertext: LweCiphertextOwned<u32>,
        enc_inter : &Encoding,
        enc_out : &Encoding,
        server_key: &ServerKey,
    ) -> Result<Ciphertext, Box<dyn Error>> {
        let (accumulator, mut buffer_lwe_after_pbs) = self.memory.as_buffers(server_key, enc_inter, enc_out);

        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        self.computation_buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        // Compute a bootstrap
        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &ciphertext,
            &mut buffer_lwe_after_pbs,
            &accumulator,
            fourier_bsk,
            fft,
            stack,
        );

        // Compute a key switch to get back to input key
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &buffer_lwe_after_pbs,
            &mut ciphertext,
        );

        Ok(Ciphertext::Encrypted(ciphertext))
    }
}