//! Module with primitives pertaining to [`SeededGlweCiphertextList`] decompression.

use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededGlweCiphertextList`] between all functions needing it.
pub fn decompress_seeded_glwe_ciphertext_list_with_existing_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_list: &mut GlweCiphertextList<OutputCont>,
    input_seeded_list: &SeededGlweCiphertextList<InputCont>,
    generator: &mut RandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    for (mut glwe_out, body_in) in output_list.iter_mut().zip(input_seeded_list.iter()) {
        let (mut output_mask, mut output_body) = glwe_out.get_mut_mask_and_body();

        // generate a uniformly random mask
        generator.fill_slice_with_random_uniform(output_mask.as_mut());
        output_body.as_mut().copy_from_slice(body_in.as_ref());
    }
}

/// Decompress a [`SeededGlweCiphertextList`], without consuming it, into a standard
/// [`GlweCiphertextList`].
pub fn decompress_seeded_glwe_ciphertext_list<Scalar, InputCont, OutputCont, Gen>(
    output_list: &mut GlweCiphertextList<OutputCont>,
    input_seeded_list: &SeededGlweCiphertextList<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut generator = RandomGenerator::<Gen>::new(input_seeded_list.compression_seed().seed);
    decompress_seeded_glwe_ciphertext_list_with_existing_generator::<_, _, _, Gen>(
        output_list,
        input_seeded_list,
        &mut generator,
    )
}
