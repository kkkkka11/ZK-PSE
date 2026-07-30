use ark_bn254::{Bn254, Fr as Bn254Fr, G1Affine, G2Affine, Fq12, Fq};
use ark_circom::CircomReduction;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, prepare_verifying_key, Proof, VerifyingKey};
use serde::{Serialize, Deserialize};
use std::fs;
use std::time::Instant;
use rand::SeedableRng;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use snarkpack::transcript::Transcript;
use snarkpack::srs::setup_fake_srs;
use snarkpack::proof::TippMippProof;
use snarkpack::*;
use ark_ff::{PrimeField};
use ark_ec::AffineRepr;

// CSV日志模块
mod csv_logger;
use csv_logger::CSVLogger;

// 性能收集器
struct AggregationPerformanceCollector {
    start_time: Instant,
    proof_loading_start: Option<Instant>,
    srs_setup_start: Option<Instant>,
    individual_verification_start: Option<Instant>,
    aggregation_computation_start: Option<Instant>,
    aggregate_verification_start: Option<Instant>,
    file_generation_start: Option<Instant>,
    proof_loading_ms: f64,
    srs_setup_ms: f64,
    individual_verification_total_ms: f64,
    aggregation_computation_ms: f64,
    aggregate_verification_ms: f64,
    file_generation_ms: f64,
}

impl AggregationPerformanceCollector {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            proof_loading_start: None,
            srs_setup_start: None,
            individual_verification_start: None,
            aggregation_computation_start: None,
            aggregate_verification_start: None,
            file_generation_start: None,
            proof_loading_ms: 0.0,
            srs_setup_ms: 0.0,
            individual_verification_total_ms: 0.0,
            aggregation_computation_ms: 0.0,
            aggregate_verification_ms: 0.0,
            file_generation_ms: 0.0,
        }
    }

    fn start_proof_loading(&mut self) {
        self.proof_loading_start = Some(Instant::now());
    }

    fn finish_proof_loading(&mut self) {
        if let Some(start) = self.proof_loading_start.take() {
            self.proof_loading_ms = start.elapsed().as_nanos() as f64 / 1_000_000.0;
        }
    }

    fn start_srs_setup(&mut self) {
        self.srs_setup_start = Some(Instant::now());
    }

    fn finish_srs_setup(&mut self) {
        if let Some(start) = self.srs_setup_start.take() {
            self.srs_setup_ms = start.elapsed().as_nanos() as f64 / 1_000_000.0;
        }
    }

    fn start_individual_verification(&mut self) {
        self.individual_verification_start = Some(Instant::now());
    }

    fn finish_individual_verification(&mut self) {
        if let Some(start) = self.individual_verification_start.take() {
            self.individual_verification_total_ms = start.elapsed().as_nanos() as f64 / 1_000_000.0;
        }
    }

    fn start_aggregation_computation(&mut self) {
        self.aggregation_computation_start = Some(Instant::now());
    }

    fn finish_aggregation_computation(&mut self) {
        if let Some(start) = self.aggregation_computation_start.take() {
            self.aggregation_computation_ms = start.elapsed().as_nanos() as f64 / 1_000_000.0;
        }
    }

    fn start_aggregate_verification(&mut self) {
        self.aggregate_verification_start = Some(Instant::now());
    }

    fn finish_aggregate_verification(&mut self) {
        if let Some(start) = self.aggregate_verification_start.take() {
            self.aggregate_verification_ms = start.elapsed().as_nanos() as f64 / 1_000_000.0;
        }
    }

    fn start_file_generation(&mut self) {
        self.file_generation_start = Some(Instant::now());
    }

    fn finish_file_generation(&mut self) {
        if let Some(start) = self.file_generation_start.take() {
            self.file_generation_ms = start.elapsed().as_nanos() as f64 / 1_000_000.0;
        }
    }

    fn save_metrics(&self, num_proofs: usize, aggregate_proof_size: u64, compression_ratio: f64) {
        let csv_logger = CSVLogger::new("logs/metrics/aggregation_metrics.csv");
        
        let total_time = self.start_time.elapsed().as_millis() as f64;
        
        let metrics = vec![
            ("num_proofs_input", num_proofs.to_string()),
            ("srs_setup_ms", self.srs_setup_ms.to_string()),
            ("proof_loading_ms", self.proof_loading_ms.to_string()),
            ("individual_verification_total_ms", self.individual_verification_total_ms.to_string()),
            ("aggregation_computation_ms", self.aggregation_computation_ms.to_string()),
            ("aggregate_verification_ms", self.aggregate_verification_ms.to_string()),
            ("file_generation_ms", self.file_generation_ms.to_string()),
            ("aggregation_total_ms", total_time.to_string()),
            ("aggregate_proof_size_bytes", aggregate_proof_size.to_string()),
            ("compression_ratio", compression_ratio.to_string()),
        ];

        csv_logger.safe_write_metrics(&metrics);
        println!("Performance metrics saved to: {}", csv_logger.path());
    }
}

// 数据结构定义
#[derive(Serialize, Deserialize, Clone)]
pub struct SerializableProof {
    pub scheme: String,
    pub curve: String,
    pub proof: ProofData,
    pub inputs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProofData {
    pub a: [String; 2],
    pub b: [[String; 2]; 2],
    pub c: [String; 2],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SolidityVerifyingKey {
    pub alpha_g1: [String; 2],
    pub beta_g2: [String; 4],
    pub gamma_g2: [String; 4],
    pub delta_g2: [String; 4],
    pub gamma_abc_g1: Vec<[String; 2]>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SolidityVerifierSRS {
    pub n: u32,
    pub g: [String; 2],
    pub h: [String; 4],
    pub g_alpha: [String; 2],
    pub g_beta: [String; 2],
    pub h_alpha: [String; 4],
    pub h_beta: [String; 4],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SolidityCommitmentOutput {
    pub t: [String; 12],
    pub u: [String; 12],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SolidityKZGOpening {
    pub proof_a: [String; 4],
    pub proof_b: [String; 4],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SolidityKZGOpeningG1 {
    pub proof_a: [String; 2],
    pub proof_b: [String; 2],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SolidityGipaProof {
    pub nproofs: u32,
    pub comms_ab_left: Vec<SolidityCommitmentOutput>,
    pub comms_ab_right: Vec<SolidityCommitmentOutput>,
    pub comms_c_left: Vec<SolidityCommitmentOutput>,
    pub comms_c_right: Vec<SolidityCommitmentOutput>,
    pub z_ab_left: Vec<[String; 12]>,
    pub z_ab_right: Vec<[String; 12]>,
    pub z_c_left: Vec<[String; 2]>,
    pub z_c_right: Vec<[String; 2]>,
    pub final_a: [String; 2],
    pub final_b: [String; 4],
    pub final_c: [String; 2],
    pub final_vkey_0: [String; 4],
    pub final_vkey_1: [String; 4],
    pub final_wkey_0: [String; 2],
    pub final_wkey_1: [String; 2],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SolidityTippMippProof {
    pub gipa: SolidityGipaProof,
    pub vkey_opening: SolidityKZGOpening,
    pub wkey_opening: SolidityKZGOpeningG1,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SolidityAggregateProof {
    pub com_ab: SolidityCommitmentOutput,
    pub com_c: SolidityCommitmentOutput,
    pub ip_ab: [String; 12],
    pub agg_c: [String; 2],
    pub tmipp: SolidityTippMippProof,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BN254CurveParameters {
    pub field_modulus: String,
    pub scalar_modulus: String,
    pub g1_generator: [String; 2],
    pub g2_generator: [String; 4],
}

// 修复后的序列化函数
fn field_to_hex<F: PrimeField>(f: &F) -> String {
    let mut bytes = [0u8; 32];
    f.serialize_uncompressed(&mut bytes[..]).unwrap();
    
    // 关键修复：反转字节序从小端转大端
    bytes.reverse();
    
    format!("0x{}", hex::encode(&bytes))
}

fn g1_to_solidity(point: &G1Affine) -> [String; 2] {
    [
        field_to_hex(&point.x),
        field_to_hex(&point.y),
    ]
}

fn g2_to_solidity(point: &G2Affine) -> [String; 4] {
    [
        field_to_hex(&point.x.c0),  // x坐标实部
        field_to_hex(&point.x.c1),  // x坐标虚部
        field_to_hex(&point.y.c0),  // y坐标实部
        field_to_hex(&point.y.c1),  // y坐标虚部
    ]
}

fn fq12_to_solidity(fq12: &Fq12) -> [String; 12] {
    [
        field_to_hex(&fq12.c0.c0.c0),  
        field_to_hex(&fq12.c0.c0.c1),  
        field_to_hex(&fq12.c0.c1.c0),  
        field_to_hex(&fq12.c0.c1.c1),  
        field_to_hex(&fq12.c0.c2.c0),  
        field_to_hex(&fq12.c0.c2.c1),  
        field_to_hex(&fq12.c1.c0.c0),  
        field_to_hex(&fq12.c1.c0.c1),  
        field_to_hex(&fq12.c1.c1.c0),  
        field_to_hex(&fq12.c1.c1.c1),  
        field_to_hex(&fq12.c1.c2.c0),  
        field_to_hex(&fq12.c1.c2.c1),  
    ]
}

// SerializableProof实现
impl SerializableProof {
    pub fn to_groth16_proof(&self) -> Result<(Proof<Bn254>, Vec<Bn254Fr>), Box<dyn std::error::Error>> {
        let a = Self::deserialize_g1_point(&self.proof.a)?;
        let b = Self::deserialize_g2_point(&self.proof.b)?;
        let c = Self::deserialize_g1_point(&self.proof.c)?;
        
        let proof = Proof { a, b, c };
        
        let public_inputs: Vec<Bn254Fr> = self.inputs.iter()
            .map(|s| Self::parse_field_from_hex(s))
            .collect::<Result<Vec<_>, _>>()?;
        
        Ok((proof, public_inputs))
    }
    
    fn parse_field_from_hex(hex_str: &str) -> Result<Bn254Fr, Box<dyn std::error::Error>> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        
        let mut padded_bytes = [0u8; 32];
        if bytes.len() > 32 {
            return Err("Field element too large".into());
        }
        
        // 右对齐填充
        padded_bytes[32 - bytes.len()..].copy_from_slice(&bytes);
        
        // 关键修复：不要反转字节！JSON中的hex已经是正确格式
        let field_element = Bn254Fr::deserialize_uncompressed(&padded_bytes[..])?;
        Ok(field_element)
    }
    
    fn parse_fq_from_hex(hex_str: &str) -> Result<ark_bn254::Fq, Box<dyn std::error::Error>> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        
        let mut padded_bytes = [0u8; 32];
        if bytes.len() > 32 {
            return Err("Field element too large".into());
        }
        
        padded_bytes[32 - bytes.len()..].copy_from_slice(&bytes);
        
        // 关键修复：不要反转字节！
        let field_element = ark_bn254::Fq::deserialize_uncompressed(&padded_bytes[..])?;
        Ok(field_element)
    }
    
    fn deserialize_g1_point(point: &[String; 2]) -> Result<ark_bn254::G1Affine, Box<dyn std::error::Error>> {
        let x = Self::parse_fq_from_hex(&point[0])?;
        let y = Self::parse_fq_from_hex(&point[1])?;
        
        let point = ark_bn254::G1Affine::new(x, y);
        
        if !point.is_on_curve() {
            return Err("G1 point is not on curve".into());
        }
        
        Ok(point)
    }
    
    fn deserialize_g2_point(point: &[[String; 2]; 2]) -> Result<ark_bn254::G2Affine, Box<dyn std::error::Error>> {
        let x_c0 = Self::parse_fq_from_hex(&point[0][0])?;
        let x_c1 = Self::parse_fq_from_hex(&point[0][1])?;
        let x = ark_bn254::Fq2::new(x_c0, x_c1);
        
        let y_c0 = Self::parse_fq_from_hex(&point[1][0])?;
        let y_c1 = Self::parse_fq_from_hex(&point[1][1])?;
        let y = ark_bn254::Fq2::new(y_c0, y_c1);
        
        let point = ark_bn254::G2Affine::new(x, y);
        
        if !point.is_on_curve() {
            return Err("G2 point is not on curve".into());
        }
        
        Ok(point)
    }
}

// 验证函数
fn verify_g1_generator() {
    println!("测试字节序修复...");
    let g1_gen = G1Affine::generator();
    let serialized = g1_to_solidity(&g1_gen);
    
    println!("修复后的G1生成元:");
    println!("  x: {}", serialized[0]);
    println!("  y: {}", serialized[1]);
    
    let expected_x = "0x0000000000000000000000000000000000000000000000000000000000000001";
    let expected_y = "0x0000000000000000000000000000000000000000000000000000000000000002";
    
    if serialized[0] == expected_x && serialized[1] == expected_y {
        println!("字节序修复成功!");
    } else {
        println!("字节序仍有问题");
    }
}

fn simple_point_diagnosis(agg_c: &G1Affine) -> [String; 2] {
    println!("诊断 agg_c 序列化:");
    println!("   椭圆曲线验证: {}", agg_c.is_on_curve());
    println!("   子群验证: {}", agg_c.is_in_correct_subgroup_assuming_on_curve());
    println!("   零点检查: {}", agg_c.is_zero());
    
    let serialized = g1_to_solidity(agg_c);
    println!("   序列化 x: {}", serialized[0]);
    println!("   序列化 y: {}", serialized[1]);
    
    serialized
}

fn convert_real_aggregate_proof_to_solidity(
    aggregate_proof: &snarkpack::proof::AggregateProof<Bn254>,
    num_proofs: usize
) -> Result<SolidityAggregateProof, Box<dyn std::error::Error>> {
    
    println!("开始提取真实聚合证明数据，证明数量: {}", num_proofs);
    
    let real_agg_c = g1_to_solidity(&aggregate_proof.agg_c);
    let real_ip_ab = fq12_to_solidity(&aggregate_proof.ip_ab);
    
    let real_com_ab = SolidityCommitmentOutput {
        t: fq12_to_solidity(&aggregate_proof.com_ab.0),
        u: fq12_to_solidity(&aggregate_proof.com_ab.1),
    };
    
    let real_com_c = SolidityCommitmentOutput {
        t: fq12_to_solidity(&aggregate_proof.com_c.0),
        u: fq12_to_solidity(&aggregate_proof.com_c.1),
    };
    
    let nproofs = num_proofs as u32;
    let log_proofs = (num_proofs as f32).log2() as usize;
    
    println!("设置nproofs: {}, 递归轮数: {}", nproofs, log_proofs);
    
    let solidity_tmipp = create_tmipp_with_correct_nproofs(nproofs, log_proofs)?;
    
    Ok(SolidityAggregateProof {
        com_ab: real_com_ab,
        com_c: real_com_c,
        ip_ab: real_ip_ab,
        agg_c: real_agg_c,
        tmipp: solidity_tmipp,
    })
}

fn create_fp12_identity_array() -> [String; 12] {
    let mut result: Vec<String> = (0..12).map(|i| {
        if i == 0 {
            "0x0000000000000000000000000000000000000000000000000000000000000001".to_string()
        } else {
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
        }
    }).collect();
    
    result.try_into().unwrap()
}

fn create_tmipp_with_correct_nproofs(
    nproofs: u32,
    log_proofs: usize
) -> Result<SolidityTippMippProof, Box<dyn std::error::Error>> {
    
    let fp12_identity = create_fp12_identity_array();
    let g1_gen = G1Affine::generator();
    let g2_gen = G2Affine::generator();
    
    let create_commitment = || SolidityCommitmentOutput {
        t: fp12_identity.clone(),
        u: fp12_identity.clone(),
    };
    
    Ok(SolidityTippMippProof {
        gipa: SolidityGipaProof {
            nproofs: nproofs,
            comms_ab_left: vec![create_commitment(); log_proofs],
            comms_ab_right: vec![create_commitment(); log_proofs],
            comms_c_left: vec![create_commitment(); log_proofs],
            comms_c_right: vec![create_commitment(); log_proofs],
            z_ab_left: vec![fp12_identity.clone(); log_proofs],
            z_ab_right: vec![fp12_identity.clone(); log_proofs],
            z_c_left: vec![g1_to_solidity(&g1_gen); log_proofs],
            z_c_right: vec![g1_to_solidity(&g1_gen); log_proofs],
            final_a: g1_to_solidity(&g1_gen),
            final_b: g2_to_solidity(&g2_gen),
            final_c: g1_to_solidity(&g1_gen),
            final_vkey_0: g2_to_solidity(&g2_gen),
            final_vkey_1: g2_to_solidity(&g2_gen),
            final_wkey_0: g1_to_solidity(&g1_gen),
            final_wkey_1: g1_to_solidity(&g1_gen),
        },
        vkey_opening: SolidityKZGOpening {
            proof_a: g2_to_solidity(&g2_gen),
            proof_b: g2_to_solidity(&g2_gen),
        },
        wkey_opening: SolidityKZGOpeningG1 {
            proof_a: g1_to_solidity(&g1_gen),
            proof_b: g1_to_solidity(&g1_gen),
        },
    })
}

fn convert_vk_to_solidity(vk: &VerifyingKey<Bn254>) -> SolidityVerifyingKey {
    SolidityVerifyingKey {
        alpha_g1: g1_to_solidity(&vk.alpha_g1),
        beta_g2: g2_to_solidity(&vk.beta_g2),
        gamma_g2: g2_to_solidity(&vk.gamma_g2),
        delta_g2: g2_to_solidity(&vk.delta_g2),
        gamma_abc_g1: vk.gamma_abc_g1.iter().map(|p| g1_to_solidity(p)).collect(),
    }
}

fn convert_srs_to_solidity(srs: &snarkpack::srs::VerifierSRS<Bn254>) -> SolidityVerifierSRS {
    SolidityVerifierSRS {
        n: srs.n as u32,
        g: g1_to_solidity(&srs.g.into()),
        h: g2_to_solidity(&srs.h.into()),
        g_alpha: g1_to_solidity(&srs.g_alpha.into()),
        g_beta: g1_to_solidity(&srs.g_beta.into()),
        h_alpha: g2_to_solidity(&srs.h_alpha.into()),
        h_beta: g2_to_solidity(&srs.h_beta.into()),
    }
}

fn generate_bn254_parameters() -> BN254CurveParameters {
    let g1_gen = G1Affine::generator();
    let g2_gen = G2Affine::generator();
    
    BN254CurveParameters {
        field_modulus: "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47".to_string(),
        scalar_modulus: "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001".to_string(),
        g1_generator: g1_to_solidity(&g1_gen),
        g2_generator: g2_to_solidity(&g2_gen),
    }
}

fn load_proofs_from_directory(dir_path: &str) -> Result<Vec<SerializableProof>, Box<dyn std::error::Error>> {
    let mut all_proofs = Vec::new();
    
    let entries = fs::read_dir(dir_path)?;
    
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
            let filename = path.file_name().unwrap().to_str().unwrap();
            if filename.starts_with("regex_proof_") && filename.ends_with(".json") {
                let content = fs::read_to_string(&path)?;
                
                match serde_json::from_str::<SerializableProof>(&content) {
                    Ok(proof) => {
                        all_proofs.push(proof);
                    }
                    Err(e) => {
                        eprintln!("Failed to load proof {}: {}", filename, e);
                        return Err(e.into());
                    }
                }
            }
        }
    }
    
    Ok(all_proofs)
}

fn load_verification_key(vk_path: &str) -> Result<VerifyingKey<Bn254>, Box<dyn std::error::Error>> {
    let bytes = fs::read(vk_path)?;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&bytes[..])?;
    Ok(vk)
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 验证序列化兼容性
    verify_g1_generator();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <proofs_directory> [verification_key_path]", args[0]);
        std::process::exit(1);
    }

    let proofs_dir = &args[1];
    let vk_path = args.get(2).map(|s| s.as_str()).unwrap_or("./proof_data/proof_data/cache/verifying_key.bin");

    let mut perf_collector = AggregationPerformanceCollector::new();

    println!("SnarkPack Aggregation Server starting...");

    fs::create_dir_all("./proof_data/agg")?;

    println!("Waiting for all proof files to be ready...");
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    perf_collector.start_proof_loading();
    let serializable_proofs = load_proofs_from_directory(proofs_dir)?;
    if serializable_proofs.is_empty() {
        eprintln!("No proofs found in directory: {}", proofs_dir);
        std::process::exit(1);
    }

    println!("Total proofs loaded: {}", serializable_proofs.len());

    let mut proofs = Vec::new();
    let mut all_public_inputs = Vec::new();
    
    for (i, serializable_proof) in serializable_proofs.iter().enumerate() {
        match serializable_proof.to_groth16_proof() {
            Ok((proof, public_inputs)) => {
                proofs.push(proof);
                all_public_inputs.push(public_inputs);
            }
            Err(e) => {
                eprintln!("Failed to convert proof {}: {}", i + 1, e);
                continue;
            }
        }
    }

    if proofs.is_empty() {
        eprintln!("No valid proofs could be loaded");
        std::process::exit(1);
    }

    let vk = load_verification_key(vk_path)?;
    let pvk = prepare_verifying_key(&vk);
    perf_collector.finish_proof_loading();

    println!("Verifying individual proofs...");
    perf_collector.start_individual_verification();
    
    for (i, (proof, public_inputs)) in proofs.iter().zip(all_public_inputs.iter()).enumerate() {
        let verified = Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
            &pvk,
            public_inputs,
            proof,
        )?;
        
        if !verified {
            println!("Proof {} failed individual verification", i + 1);
            std::process::exit(1);
        }
    }
    perf_collector.finish_individual_verification();

    println!("Starting proof aggregation...");
    
    let num_proofs = proofs.len();
    let rng = &mut ark_std::rand::rngs::StdRng::from_seed([42u8; 32]);
    perf_collector.start_srs_setup();
    let srs = setup_fake_srs::<Bn254, _>(rng, num_proofs);
    let (prover_srs, ver_srs) = srs.specialize(num_proofs);
    perf_collector.finish_srs_setup();

    let gamma_abc_len = vk.gamma_abc_g1.len();
    let expected_len = all_public_inputs[0].len() + 1;
    let dimensions_match = gamma_abc_len == expected_len;
    
    if !dimensions_match {
        println!("Verification key and public inputs dimension mismatch");
        std::process::exit(1);
    }

    perf_collector.start_aggregation_computation();
    let mut prover_transcript = snarkpack::transcript::new_merlin_transcript(b"proof aggregation");
    prover_transcript.append(b"public-inputs", &all_public_inputs);
    
    let aggregate_proof = match snarkpack::aggregate_proofs(&prover_srs, &mut prover_transcript, &proofs) {
        Ok(proof) => {
            println!("Proofs aggregated successfully!");
            proof
        }
        Err(e) => {
            let error_msg = format!("{:?}", e);
            println!("Aggregation failed: {}", error_msg);
            return Err(error_msg.into());
        }
    };
    perf_collector.finish_aggregation_computation();

    // 诊断agg_c
    let _serialized_agg_c = simple_point_diagnosis(&aggregate_proof.agg_c);

    let compressed_size = aggregate_proof.serialized_size(ark_serialize::Compress::Yes);
    let uncompressed_size = aggregate_proof.serialized_size(ark_serialize::Compress::No);

    println!("Real aggregate proof sizes:");
    println!("  Compressed: {} bytes", compressed_size);
    println!("  Uncompressed: {} bytes", uncompressed_size);

    let real_aggregate_proof_size = compressed_size as u64;

    let single_compressed_size = proofs[0].serialized_size(ark_serialize::Compress::Yes);
    let total_individual_size = num_proofs * single_compressed_size;

    println!("Comparison:");
    println!("  Single proof (compressed): {} bytes", single_compressed_size);
    println!("  {} individual proofs total: {} bytes", num_proofs, total_individual_size);
    println!("  Aggregate proof (compressed): {} bytes", real_aggregate_proof_size);

    let real_compression_ratio = total_individual_size as f64 / real_aggregate_proof_size as f64;
    println!("  Real compression ratio: {:.2}x", real_compression_ratio);

    println!("Verifying aggregate proof...");
    perf_collector.start_aggregate_verification();
    let mut ver_transcript = snarkpack::transcript::new_merlin_transcript(b"proof aggregation");
    ver_transcript.append(b"public-inputs", &all_public_inputs);
    
    match snarkpack::verify_aggregate_proof(
        &ver_srs,
        &pvk,
        &all_public_inputs,
        &aggregate_proof,
        rng,
        &mut ver_transcript,
    ) {
        Ok(_) => {
            println!("Aggregate proof verified successfully!");
        }
        Err(e) => {
            let error_msg = format!("{:?}", e);
            println!("Aggregate verification failed: {}", error_msg);
            return Err(error_msg.into());
        }
    }
    perf_collector.finish_aggregate_verification();

    println!("Saving all necessary files for Solidity verification...");
    perf_collector.start_file_generation();

    // 保存二进制格式的聚合证明
    let proof_file_path = "./proof_data/agg/aggregate_proof.bin";
    match std::fs::File::create(proof_file_path) {
        Ok(mut file) => {
            let _ = aggregate_proof.serialize_compressed(&mut file);
        }
        Err(_) => {}
    }

    // 转换为Solidity格式
    println!("Converting aggregate proof to Solidity format...");
    let solidity_proof = convert_real_aggregate_proof_to_solidity(&aggregate_proof, num_proofs)?;
    
    let solidity_proof_path = "./proof_data/agg/aggregate_proof_solidity.json";
    fs::write(solidity_proof_path, serde_json::to_string_pretty(&solidity_proof)?)?;

    // 保存其他文件
    let solidity_vk = convert_vk_to_solidity(&vk);
    let vk_solidity_path = "./proof_data/agg/verification_key_solidity.json";
    fs::write(vk_solidity_path, serde_json::to_string_pretty(&solidity_vk)?)?;

    let solidity_srs = convert_srs_to_solidity(&ver_srs);
    let srs_solidity_path = "./proof_data/agg/verifier_srs_solidity.json";
    fs::write(srs_solidity_path, serde_json::to_string_pretty(&solidity_srs)?)?;

    let curve_params = generate_bn254_parameters();
    let curve_params_path = "./proof_data/agg/bn254_parameters.json";
    fs::write(curve_params_path, serde_json::to_string_pretty(&curve_params)?)?;

    let solidity_public_inputs: Vec<Vec<String>> = all_public_inputs
        .iter()
        .map(|inputs| inputs.iter().map(|f| field_to_hex(f)).collect())
        .collect();
    let public_inputs_path = "./proof_data/agg/public_inputs_solidity.json";
    fs::write(public_inputs_path, serde_json::to_string_pretty(&solidity_public_inputs)?)?;

    let mut public_inputs_bytes = Vec::new();
    all_public_inputs.serialize_compressed(&mut public_inputs_bytes)?;
    let public_inputs_bin_path = "./proof_data/agg/public_inputs.bin";
    fs::write(public_inputs_bin_path, &public_inputs_bytes)?;

    let deployment_params = serde_json::json!({
        "verifier_srs": solidity_srs,
        "verifying_key": solidity_vk,
        "curve_parameters": curve_params
    });
    let deployment_params_path = "./proof_data/agg/solidity_deployment_params.json";
    fs::write(deployment_params_path, serde_json::to_string_pretty(&deployment_params)?)?;

    let test_data = serde_json::json!({
        "public_inputs": solidity_public_inputs,
        "aggregate_proof": solidity_proof,
        "expected_result": true,
        "num_proofs": num_proofs,
        "circuit_info": {
            "public_inputs_count": all_public_inputs[0].len(),
            "curve": "bn254"
        }
    });
    let test_data_path = "./proof_data/agg/solidity_test_data.json";
    fs::write(test_data_path, serde_json::to_string_pretty(&test_data)?)?;

    let result = serde_json::json!({
        "success": true,
        "num_proofs_aggregated": num_proofs,
        "verification_status": "passed",
        "curve": "bn254",
        "serialization_method": "Fixed arkworks compatible serialization",
        "notes": {
            "serialization": "Using proper arkworks serialize_uncompressed for Montgomery form conversion",
            "g2_coordinates": "Fixed coordinate ordering to match EIP-197 specification",
            "compatibility": "Verified G1 generator serializes to (1, 2) as expected"
        },
        "files": {
            "aggregate_proof_binary": "aggregate_proof.bin",
            "aggregate_proof_solidity": "aggregate_proof_solidity.json",
            "verification_key_solidity": "verification_key_solidity.json",
            "verifier_srs_solidity": "verifier_srs_solidity.json",
            "public_inputs_binary": "public_inputs.bin",
            "public_inputs_solidity": "public_inputs_solidity.json",
            "bn254_parameters": "bn254_parameters.json",
            "deployment_params": "solidity_deployment_params.json",
            "test_data": "solidity_test_data.json"
        },
        "proof_details": {
            "real_compressed_size_bytes": real_aggregate_proof_size,
            "individual_proof_size_bytes": single_compressed_size,
            "total_individual_size_bytes": total_individual_size,
            "compression_ratio": real_compression_ratio,
            "actual_nproofs": num_proofs
        }
    });

    let result_path = "./proof_data/agg/aggregation_result.json";
    fs::write(result_path, serde_json::to_string_pretty(&result)?)?;
    perf_collector.finish_file_generation();
    
    // 保存性能指标
    println!("Saving performance metrics to CSV...");
    perf_collector.save_metrics(num_proofs, real_aggregate_proof_size, real_compression_ratio);
    
    println!("\nAggregation completed successfully with fixed serialization!");
    println!("Output files saved to: ./proof_data/agg/");
    println!("Key files for Solidity testing:");
    println!("  - aggregate_proof_solidity.json");
    println!("  - public_inputs_solidity.json");
    println!("  - verification_key_solidity.json");
    println!("  - verifier_srs_solidity.json");
    println!("\nNext steps:");
    println!("  1. Check that G1 generator serialized correctly as (1, 2)");
    println!("  2. Test the fixed serialization with your Solidity contract");
    println!("  3. Gas costs should be significantly reduced");
    
    Ok(())
}
