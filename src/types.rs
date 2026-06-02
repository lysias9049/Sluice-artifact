/// A single nonzero entry (row, col, value) in an R1CS matrix.
/// Stored in column-sorted order for streaming witness access.
pub type R1csEntry<F> = (usize, usize, F);

/// One of the three R1CS matrices (U, V, or W).
/// Elements are tuples `(constraint_idx, wire_idx, value)` sorted by `wire_idx`.
pub type R1csMatrix<F> = Vec<R1csEntry<F>>;

/// A Quadratic Arithmetic Program instance.
///
/// Represents an R1CS relation over a prime field F with:
/// - `n_constraints` (= domain size after padding to power of two, denoted N)
/// - `n_vars` total wires (including the constant wire 0)
/// - `n_pub` public input/output wires (indices 1..=n_pub)
/// - Three sparse matrices U, V, W each in column-sorted order
pub struct Qap<F: ark_ff::Field> {
    /// Padded domain size: N = 2^⌈log₂(n_constraints)⌉.
    pub domain_size: usize,
    /// Total number of constraints (rows of U/V/W).
    pub n_constraints: usize,
    /// Total number of wires including the constant wire a_0 = 1.
    pub n_vars: usize,
    /// Number of public inputs ℓ (wires a_1 … a_ℓ).
    pub n_pub: usize,

    /// Matrix U: coefficients of A(X) = Σ aᵢ uᵢ(X), column-sorted.
    pub u: R1csMatrix<F>,
    /// Matrix V: coefficients of B(X) = Σ aᵢ vᵢ(X), column-sorted.
    pub v: R1csMatrix<F>,
    /// Matrix W: coefficients of C(X) = Σ aᵢ wᵢ(X), column-sorted.
    pub w: R1csMatrix<F>,
}

/// Proving key for RW-Groth16.
///
/// All CRS group-element streams are stored as `Vec`s in streaming order
/// (one contiguous sequence per MSM). For large circuits these should be
/// replaced by `FileVec<G1Affine>` / `FileVec<G2Affine>` backed by disk.
pub struct ProvingKey<E: ark_ec::pairing::Pairing> {
    // ── G₁ streams ──────────────────────────────────────────────────────────
    /// [uᵢ(τ)]₁  for i = 0..n_vars-1   (used in MSM for [A]₁)
    pub g1_u_tau: Vec<E::G1Affine>,
    /// [vᵢ(τ)]₁  for i = 0..n_vars-1   (auxiliary, used in [C]₁)
    pub g1_v_tau: Vec<E::G1Affine>,
    /// [(β·uᵢ(τ) + α·vᵢ(τ) + wᵢ(τ))/δ]₁  for i = n_pub+1..n_vars-1
    pub g1_abc_over_delta: Vec<E::G1Affine>,
    /// [τʲ·t(τ)/δ]₁  for j = 0..N-2   (used in quotient MSM)
    pub g1_h_pow_tau_over_delta: Vec<E::G1Affine>,
    /// [α]₁, [β]₁, [δ]₁
    pub g1_alpha: E::G1Affine,
    pub g1_beta: E::G1Affine,
    pub g1_delta: E::G1Affine,

    // ── G₂ streams ──────────────────────────────────────────────────────────
    /// [vᵢ(τ)]₂  for i = 0..n_vars-1   (used in MSM for [B]₂)
    pub g2_v_tau: Vec<E::G2Affine>,
    /// [β]₂, [δ]₂
    pub g2_beta: E::G2Affine,
    pub g2_delta: E::G2Affine,
}

/// Verification key (identical to standard Groth16).
pub struct VerifyingKey<E: ark_ec::pairing::Pairing> {
    pub alpha_g1: E::G1Affine,
    pub beta_g2: E::G2Affine,
    pub gamma_g2: E::G2Affine,
    pub delta_g2: E::G2Affine,
    /// [(β·uᵢ(τ) + α·vᵢ(τ) + wᵢ(τ))/γ]₁ for i = 0..n_pub
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

/// Groth16 proof: three group elements.
#[derive(Clone, Debug)]
pub struct Proof<E: ark_ec::pairing::Pairing> {
    pub a: E::G1Affine,
    pub b: E::G2Affine,
    pub c: E::G1Affine,
}

/// A QAP with matrices stored on disk (`FileVec<MatrixEntry<F>>`, col-sorted).
///
/// Created by `setup::make_streaming_qap`.  After creation the in-memory
/// `Qap` can be dropped, freeing O(N) RAM.  Only O(1) metadata stays in RAM.
pub struct StreamingQap<F>
where
    F: ark_ff::FftField + crate::file_vec::StreamElem + Copy,
{
    pub domain_size: usize,
    pub n_constraints: usize,
    pub n_vars: usize,
    pub n_pub: usize,
    /// Matrix U — col-sorted, on disk.
    pub u: crate::file_vec::FileVec<crate::file_vec::MatrixEntry<F>>,
    /// Matrix V — col-sorted, on disk.
    pub v: crate::file_vec::FileVec<crate::file_vec::MatrixEntry<F>>,
    /// Matrix W — col-sorted, on disk.
    pub w: crate::file_vec::FileVec<crate::file_vec::MatrixEntry<F>>,
}

/// Proving key for RW-Groth16 with CRS stored on disk (FileVec).
///
/// All large G₁/G₂ arrays live on disk via `G1Disk`/`G2Disk` newtypes;
/// only O(1) group elements are in RAM.
/// Use with `streaming_setup` and `streaming_prove_disk`.
///
/// Note: BN254-specific — uses `G1Disk`/`G2Disk` wrappers so that
/// `StreamElem` can be implemented for the curve affine types without
/// running into Rust's coherence restrictions on `Affine<_>`.
pub struct StreamingProvingKey<E: ark_ec::pairing::Pairing> {
    // ── Disk-backed CRS streams ──────────────────────────────────────────────
    /// [uᵢ(τ)]₁  for i = 0..n_vars-1   (used in MSM for [A]₁)
    pub g1_u_tau: crate::file_vec::FileVec<crate::file_vec::G1Disk>,
    /// [vᵢ(τ)]₁  for i = 0..n_vars-1   (auxiliary, used in [C]₁)
    pub g1_v_tau: crate::file_vec::FileVec<crate::file_vec::G1Disk>,
    /// [(β·uᵢ(τ) + α·vᵢ(τ) + wᵢ(τ))/δ]₁  for i = n_pub+1..n_vars-1
    pub g1_abc_over_delta: crate::file_vec::FileVec<crate::file_vec::G1Disk>,
    /// [τʲ·t(τ)/δ]₁  for j = 0..N-2
    pub g1_h_pow_tau_over_delta: crate::file_vec::FileVec<crate::file_vec::G1Disk>,
    /// [vᵢ(τ)]₂  for i = 0..n_vars-1   (used in MSM for [B]₂)
    pub g2_v_tau: crate::file_vec::FileVec<crate::file_vec::G2Disk>,

    // ── Small constants (in RAM) ─────────────────────────────────────────────
    pub g1_alpha: E::G1Affine,
    pub g1_beta: E::G1Affine,
    pub g1_delta: E::G1Affine,
    pub g2_beta: E::G2Affine,
    pub g2_delta: E::G2Affine,

    // ── Metadata ─────────────────────────────────────────────────────────────
    /// Number of public inputs ℓ.
    pub n_pub: usize,
}
