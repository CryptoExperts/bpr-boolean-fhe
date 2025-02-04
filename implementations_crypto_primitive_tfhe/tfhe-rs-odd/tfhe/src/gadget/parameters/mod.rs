//! The cryptographic parameter set.
//!
//! This module provides the structure containing the cryptographic parameters required for the
//! homomorphic evaluation of Boolean circuit as well as a list of secure cryptographic parameter
//! sets.
//!
//! Two parameter sets are provided:
//!  * `tfhe::boolean::parameters::DEFAULT_PARAMETERS`
//!  * `tfhe::boolean::parameters::TFHE_LIB_PARAMETERS`
//!
//! They ensure the correctness of the Boolean circuit evaluation result (up to a certain
//! probability) along with 128-bits of security.
//!
//! The two parameter sets offer a trade-off in terms of execution time versus error probability.
//! The `DEFAULT_PARAMETERS` set offers better performances on homomorphic circuit evaluation
//! with an higher probability error in comparison with the `TFHE_LIB_PARAMETERS`.
//! Note that if you desire, you can also create your own set of parameters.
//! This is an unsafe operation as failing to properly fix the parameters will potentially result
//! with an incorrect and/or insecure computation.

use crate::boolean::prelude::EncryptionKeyChoice;
pub use crate::core_crypto::commons::dispersion::StandardDev;
pub use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use serde::{Deserialize, Serialize};

/// A set of cryptographic parameters for homomorphic Boolean circuit evaluation.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BooleanParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_modular_std_dev: StandardDev,
    pub glwe_modular_std_dev: StandardDev,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub encryption_key_choice: EncryptionKeyChoice
}

impl BooleanParameters {
    /// Constructs a new set of parameters for boolean circuit evaluation.
    ///
    /// # Safety
    ///
    /// This function is unsafe, as failing to fix the parameters properly would yield incorrect
    /// and insecure computation. Unless you are a cryptographer who really knows the impact of each
    /// of those parameters, you __must__ stick with the provided parameters [`DEFAULT_PARAMETERS`]
    /// and [`TFHE_LIB_PARAMETERS`], which both offer correct results with 128 bits of security.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn new(
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        lwe_modular_std_dev: StandardDev,
        glwe_modular_std_dev: StandardDev,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
        encryption_key_choice: EncryptionKeyChoice
    ) -> BooleanParameters {
        BooleanParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_level,
            ks_base_log,
            encryption_key_choice
        }
    }
}
/// Default parameter set.
///
/// This parameter set ensures 128-bits of security, and a probability of error is upper-bounded by
/// $2^{-40}$. The secret keys generated with this parameter set are uniform binary.
/// This parameter set allows to evaluate faster Boolean circuits than the `TFHE_LIB_PARAMETERS`
/// one.
pub const DEFAULT_PARAMETERS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(722),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.000013071021089943935),
    glwe_modular_std_dev: StandardDev(0.00000004990272175010415),
    pbs_base_log: DecompositionBaseLog(6),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    encryption_key_choice: EncryptionKeyChoice::Small,
};



// Parameters Eurocrypt
pub const SIMON_PARAMETERS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(774),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.0000021515145918907506),
    glwe_modular_std_dev: StandardDev(0.0000000000000000002168404344971009),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    encryption_key_choice: EncryptionKeyChoice::Small,

};

// Parameters with AP framework : error probability = 2^-23:
pub const SIMON_PARAMETERS_23: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(664),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.00000000145030188251153),
    glwe_modular_std_dev: StandardDev(0.000000000000002490281638068318),
    pbs_base_log: DecompositionBaseLog(6),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    encryption_key_choice: EncryptionKeyChoice::Big,

};


// Parameters with AP framework : error probability = 2^-40:
pub const SIMON_PARAMETERS_40: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(684),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.0000000006936956471072121),
    glwe_modular_std_dev: StandardDev(0.0000000000000000008673617379884035),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    encryption_key_choice: EncryptionKeyChoice::Big,

};



//papier Zama Trivium
pub const ZAMA_TRIVIUM_PARAMETERS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(684),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.0000204378),
    glwe_modular_std_dev: StandardDev(0.000000000000345253),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    encryption_key_choice: EncryptionKeyChoice::Small,

};

/////Paramètres papier Eurocrypt
pub const ASCON_PARAMETERS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(768),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000003725679281679651),
    glwe_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    encryption_key_choice: EncryptionKeyChoice::Small,

};


////Paramètres proba erreyr 2^-40
pub const ASCON_PARAMETERS_40: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(740),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.00000000008797484970256741),
    glwe_modular_std_dev: StandardDev(0.0000000000000000008673617379884035),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    encryption_key_choice: EncryptionKeyChoice::Big,

};


/////Paramètres papier Eurocrypt
pub const SHA3_PARAMETERS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(668),
    glwe_dimension: GlweDimension(6),
    polynomial_size: PolynomialSize(256),
    lwe_modular_std_dev: StandardDev(0.000003725679281679651),
    glwe_modular_std_dev: StandardDev(0.0000000000034525330484572114),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    encryption_key_choice: EncryptionKeyChoice::Small,

};

//parameters for 40 bits of security
pub const SHA3_PARAMETERS_40: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(676),
    glwe_dimension: GlweDimension(5),
    polynomial_size: PolynomialSize(256),
    lwe_modular_std_dev: StandardDev(0.0000000009317185580308595),
    glwe_modular_std_dev: StandardDev(0.0000000000000000008673617379884035),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    encryption_key_choice: EncryptionKeyChoice::Big,

};



// Paramètres version Eurocrypt
pub const AES_PARAMETERS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(807),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_modular_std_dev: StandardDev(2.15e-6),
    glwe_modular_std_dev: StandardDev(2.16e-19),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(5),
    encryption_key_choice: EncryptionKeyChoice::Small,
};


pub const AES_PARAMETERS_40: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(708),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.000000000002863001922944826),
    glwe_modular_std_dev: StandardDev(0.0000000000000000008673617379884035),
    pbs_base_log: DecompositionBaseLog(6),
    pbs_level: DecompositionLevelCount(4),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(2),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const AES_PARAMETERS_23: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(672),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_modular_std_dev: StandardDev(0.0000000010797982869590127),
    glwe_modular_std_dev: StandardDev(0.0000000000000000008673617379884035),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    encryption_key_choice: EncryptionKeyChoice::Big,
};



/// The secret keys generated with this parameter set are uniform binary.
/// This parameter set ensures a probability of error upper-bounded by $2^{-165}$ as the ones
/// proposed into [TFHE library](https://tfhe.github.io/tfhe/) for for 128-bits of security.
/// They are updated to the last security standards, so they differ from the original
/// publication.
pub const TFHE_LIB_PARAMETERS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(830),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(0.000001412290588219445),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
