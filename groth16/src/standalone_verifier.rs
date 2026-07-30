use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_circom::CircomReduction;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, prepare_verifying_key, VerifyingKey};
use std::fs;
use ark_serialize::CanonicalDeserialize;
use snarkpack::transcript::Transcript;
use snarkpack::srs::setup_fake_srs;
use snarkpack::proof::AggregateProof;
use rand::SeedableRng;

fn load_aggregate_proof(path: &str) -> Result<AggregateProof<Bn254>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let proof = AggregateProof::<Bn254>::deserialize_compressed(&bytes[..])?;
    Ok(proof)
}

fn load_verification_key(path: &str) -> Result<VerifyingKey<Bn254>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&bytes[..])?;
    Ok(vk)
}

fn load_public_inputs(path: &str) -> Result<Vec<Vec<Bn254Fr>>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let public_inputs = Vec::<Vec<Bn254Fr>>::deserialize_compressed(&bytes[..])?;
    Ok(public_inputs)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() != 5 {
        eprintln!("Usage: {} <aggregate_proof.bin> <verifying_key.bin> <public_inputs.bin> <num_proofs>", args[0]);
        eprintln!("Example: {} ./proof_data/agg/aggregate_proof.bin ./proof_data/agg/verifying_key.bin ./proof_data/agg/public_inputs.bin 4", args[0]);
        std::process::exit(1);
    }

    let proof_path = &args[1];
    let vk_path = &args[2];
    let inputs_path = &args[3];
    let num_proofs: usize = args[4].parse().map_err(|_| "Invalid number of proofs")?;

    println!("Loading aggregate proof from: {}", proof_path);
    let aggregate_proof = load_aggregate_proof(proof_path)?;

    println!("Loading verification key from: {}", vk_path);
    let vk = load_verification_key(vk_path)?;

    println!("Loading public inputs from: {}", inputs_path);
    let all_public_inputs = load_public_inputs(inputs_path)?;

    if all_public_inputs.len() != num_proofs {
        eprintln!("Error: Expected {} proofs, but found {} public input sets", 
                 num_proofs, all_public_inputs.len());
        std::process::exit(1);
    }

    println!("Preparing verification key...");
    let pvk = prepare_verifying_key(&vk);

    println!("Setting up SRS for {} proofs...", num_proofs);
    let rng = &mut ark_std::rand::rngs::StdRng::from_seed([42u8; 32]);
    let srs = setup_fake_srs::<Bn254, _>(rng, num_proofs);
    let (_, ver_srs) = srs.specialize(num_proofs);

    println!("Creating verification transcript...");
    let mut ver_transcript = snarkpack::transcript::new_merlin_transcript(b"proof aggregation");
    ver_transcript.append(b"public-inputs", &all_public_inputs);

    println!("Verifying aggregate proof...");
    let start_time = std::time::Instant::now();
    
    match snarkpack::verify_aggregate_proof(
        &ver_srs,
        &pvk,
        &all_public_inputs,
        &aggregate_proof,
        rng,
        &mut ver_transcript,
    ) {
        Ok(_) => {
            let verification_time = start_time.elapsed();
            println!("✅ Aggregate proof verified successfully!");
            println!("Verification time: {:?}", verification_time);
            println!("Number of proofs verified: {}", num_proofs);
            std::process::exit(0);
        }
        Err(e) => {
            let verification_time = start_time.elapsed();
            println!("❌ Aggregate proof verification failed!");
            println!("Error: {:?}", e);
            println!("Verification time: {:?}", verification_time);
            std::process::exit(1);
        }
    }
}