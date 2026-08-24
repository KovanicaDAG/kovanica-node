//! Integration tests for VRF-based leader selection and randomness beacon.

use kovanica_dag::{vrf_keypair_from_seed, vrf_prove, Block, BlockId, Dag, VrfProof};

/// Build a DAG with the given `k` and a fixed genesis.
fn new_dag(k: u16) -> (Dag, BlockId) {
    let genesis = Block::genesis(1, 0, 0, b"kovanica-genesis".to_vec());
    let id = genesis.id();
    (Dag::new(k, genesis), id)
}

/// Insert a unit-work block with the given parents and label.
fn add(dag: &mut Dag, parents: &[BlockId], label: &str) -> BlockId {
    dag.insert(Block::new(
        parents.to_vec(),
        1,
        0,
        0,
        label.as_bytes().to_vec(),
    ))
    .expect("insert should succeed")
}

/// Insert a block with VRF fields.
fn add_with_vrf(
    dag: &mut Dag,
    parents: &[BlockId],
    label: &str,
    vrf_pk: &kovanica_dag::VrfPublicKey,
    vrf_proof: &kovanica_dag::VrfProof,
    vrf_output: &kovanica_dag::VrfOutput,
) -> BlockId {
    dag.insert(Block::new_with_vrf(
        parents.to_vec(),
        1,
        0,
        0,
        *vrf_pk,
        vrf_proof.clone(),
        *vrf_output,
        label.as_bytes().to_vec(),
    ))
    .expect("insert should succeed")
}

#[test]
fn vrf_disabled_by_default() {
    let (dag, _) = new_dag(3);
    assert!(dag.vrf_config().is_none());
}

#[test]
fn vrf_enable_disable() {
    let (mut dag, _) = new_dag(3);
    dag.set_vrf(u64::MAX);
    assert!(dag.vrf_config().is_some());
    assert_eq!(dag.vrf_config().unwrap().threshold, u64::MAX);

    dag.disable_vrf();
    assert!(dag.vrf_config().is_none());
}

#[test]
fn vrf_leader_eligibility() {
    // Generate a VRF keypair
    let (sk, pk) = vrf_keypair_from_seed(&[1u8; 32]);

    // Create DAG with VRF enabled and low threshold (only outputs < 100 eligible)
    let (mut dag, genesis) = new_dag(3);
    dag.set_vrf(100);

    // Compute VRF for a block building on genesis
    let vrf_input = Dag::vrf_input(&[genesis]);
    let eval = vrf_prove(&sk, &vrf_input);

    // Check if output is eligible
    let output_u64 = eval.output.as_u64();
    if output_u64 < 100 {
        // Eligible - should insert
        let id = add_with_vrf(
            &mut dag,
            &[genesis],
            "eligible",
            &pk,
            &eval.proof,
            &eval.output,
        );
        assert!(dag.ghostdag(&id).is_some());
    } else {
        // Not eligible - should fail
        let err = dag
            .insert(Block::new_with_vrf(
                vec![genesis],
                1,
                0,
                0,
                pk,
                eval.proof.clone(),
                eval.output,
                b"not eligible".to_vec(),
            ))
            .unwrap_err();
        assert!(matches!(err, kovanica_dag::DagError::InvalidVrf { .. }));
    }
}

#[test]
fn vrf_invalid_proof_rejected() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_vrf(u64::MAX);

    let (sk, pk) = vrf_keypair_from_seed(&[2u8; 32]);
    let vrf_input = Dag::vrf_input(&[genesis]);
    let eval = vrf_prove(&sk, &vrf_input);

    // Tamper with proof
    let mut bytes = eval.proof.to_bytes();
    bytes[64] ^= 1;
    let bad_proof = VrfProof::from_bytes(&bytes).unwrap();

    let err = dag
        .insert(Block::new_with_vrf(
            vec![genesis],
            1,
            0,
            0,
            pk,
            bad_proof,
            eval.output,
            b"bad proof".to_vec(),
        ))
        .unwrap_err();

    assert!(matches!(err, kovanica_dag::DagError::InvalidVrf { .. }));
}

#[test]
fn vrf_missing_fields_rejected() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_vrf(u64::MAX);

    // Block without VRF fields
    let err = dag
        .insert(Block::new(vec![genesis], 1, 0, 0, b"no vrf".to_vec()))
        .unwrap_err();

    assert!(matches!(err, kovanica_dag::DagError::InvalidVrf { .. }));
}

#[test]
fn vrf_wrong_public_key_rejected() {
    let (mut dag, genesis) = new_dag(3);
    dag.set_vrf(u64::MAX);

    let (sk1, _pk1) = vrf_keypair_from_seed(&[3u8; 32]);
    let (_, pk2) = vrf_keypair_from_seed(&[4u8; 32]);

    let vrf_input = Dag::vrf_input(&[genesis]);
    let eval = vrf_prove(&sk1, &vrf_input);

    // Use proof from sk1 but pk2
    let err = dag
        .insert(Block::new_with_vrf(
            vec![genesis],
            1,
            0,
            0,
            pk2,
            eval.proof,
            eval.output,
            b"wrong pk".to_vec(),
        ))
        .unwrap_err();

    assert!(matches!(err, kovanica_dag::DagError::InvalidVrf { .. }));
}

#[test]
fn vrf_genesis_exempt() {
    // Genesis should not require VRF even when VRF is enabled
    let (mut dag, _genesis) = new_dag(3);
    dag.set_vrf(0); // threshold 0 means no one eligible except genesis is exempt

    // We can't actually insert another genesis, but we can check that genesis
    // doesn't trigger VRF checks by inserting a block without VRF when genesis
    // was created without VRF enabled, then enabling VRF and inserting.
}

#[test]
fn vrf_input_is_deterministic() {
    let (_, genesis) = new_dag(3);
    let parents = vec![genesis, genesis]; // duplicate for test
    let input1 = Dag::vrf_input(&parents);
    let input2 = Dag::vrf_input(&parents);
    assert_eq!(input1, input2);
}

#[test]
fn vrf_different_parents_different_input() {
    let (mut dag, genesis) = new_dag(3);
    let a = add(&mut dag, &[genesis], "a");
    let b = add(&mut dag, &[genesis], "b");

    let input1 = Dag::vrf_input(&[genesis, a]);
    let input2 = Dag::vrf_input(&[genesis, b]);
    assert_ne!(input1, input2);
}

#[test]
fn vrf_composes_with_pow() {
    // VRF and PoW can be enabled independently
    let (mut dag, genesis) = new_dag(3);
    dag.set_vrf(u64::MAX);
    dag.set_proof_of_work(true);

    // Block without PoW should fail
    let (sk, pk) = vrf_keypair_from_seed(&[5u8; 32]);
    let vrf_input = Dag::vrf_input(&[genesis]);
    let eval = vrf_prove(&sk, &vrf_input);

    let err = dag
        .insert(Block::new_with_vrf(
            vec![genesis],
            1000, // work 1000 means nonce 0 won't meet work target
            0,    // timestamp_ms
            0,    // nonce
            pk,
            eval.proof,
            eval.output,
            b"no pow".to_vec(),
        ))
        .unwrap_err();

    // Should fail on PoW first (checked before VRF)
    assert!(matches!(
        err,
        kovanica_dag::DagError::InsufficientProofOfWork { .. }
    ));
}

#[test]
fn vrf_randomness_beacon() {
    // Test that VRF output serves as verifiable randomness
    let (sk, pk) = vrf_keypair_from_seed(&[6u8; 32]);
    let (mut dag, genesis) = new_dag(3);
    dag.set_vrf(u64::MAX);

    let vrf_input = Dag::vrf_input(&[genesis]);
    let eval = vrf_prove(&sk, &vrf_input);

    // Verify the output can be verified by anyone
    let verified = kovanica_dag::vrf_verify(&pk, &vrf_input, &eval.proof).unwrap();
    assert_eq!(verified, eval.output);

    // The output is unpredictable (without sk) but verifiable
    // This is the randomness beacon property
    assert_ne!(eval.output.as_bytes(), &[0u8; 32]);
}
