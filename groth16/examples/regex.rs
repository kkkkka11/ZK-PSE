use ark_bn254::{Bn254, Fr as Bn254Fr, G1Projective as G1, G2Projective as G2};
use ark_bn254::{G1Affine, G2Affine, Fq, Fq2};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, AffineRepr};
use ark_ff::{BigInt, UniformRand, PrimeField, BigInteger};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_poly::EvaluationDomain;
use ark_poly::Radix2EvaluationDomain;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::{cfg_chunks, cfg_into_iter, end_timer, start_timer, One, Zero};
use std::sync::Arc;
use tokio::sync::Barrier;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::time::Instant;
use serde_json::{json, Value};
use std::path::Path;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Compress};
// 序列化导入
use serde::{Serialize, Deserialize};
// MPC 相关导入
use dist_primitives::dfft::FftMask;
use dist_primitives::dmsm::MsmMask;
use dist_primitives::utils::deg_red::DegRedMask;
use groth16::qap::qap;
use groth16::{ext_wit, qap};
use mpc_net::{InMemoryTestNet as Net, MpcNet, MultiplexedStreamID};

use rand::SeedableRng;
use secret_sharing::pss::PackedSharingParams;
use groth16::proving_key::PackedProvingKeyShare;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

// CSV日志模块
use groth16::csv_logger::{CSVLogger, PerfTimer};

// Witness 结构体
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Witness {
    pub password: String,
    pub k: String,
}

impl Witness {
    // 将密码转换为字节数组
    pub fn password_to_bytes(&self, target_length: usize) -> Vec<u8> {
        let password_bytes = self.password.as_bytes();
        let mut msg_array = vec![0u8; target_length];
        
        for (i, &byte) in password_bytes.iter().enumerate() {
            if i < target_length {
                msg_array[i] = byte;
            }
        }
        
        msg_array
    }
    
    // 将k转换为整数值
    pub fn k_to_int(&self) -> i64 {
        // 计算k字符串的简单哈希值
        let k_bytes = self.k.as_bytes();
        let mut hash: i64 = 0;
        
        for (i, &byte) in k_bytes.iter().enumerate() {
            if i >= 8 { break; } // 只使用前8个字节
            hash = hash.wrapping_mul(256).wrapping_add(byte as i64);
        }
        
        hash
    }
    
    // 从文件读取witness
    pub fn from_file(file_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(file_path)?;
        let witness: Witness = serde_json::from_str(&content)?;
        Ok(witness)
    }
}

// 序列化结构体
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

impl SerializableProof {
    pub fn from_groth16_proof(proof: &Proof<Bn254>, public_inputs: &[Bn254Fr]) -> Self {
        SerializableProof {
            scheme: "g16".to_string(),
            curve: "bn128".to_string(),
            proof: ProofData {
                a: Self::serialize_g1_point(&proof.a),
                b: Self::serialize_g2_point(&proof.b),
                c: Self::serialize_g1_point(&proof.c),
            },
            inputs: public_inputs.iter()
                .map(|x| Self::field_to_hex(x))
                .collect(),
        }
    }
    
    fn field_to_hex(field: &Bn254Fr) -> String {
        let bigint = field.into_bigint();
        let bytes = bigint.to_bytes_le();
        format!("0x{}", hex::encode(bytes))
    }
    
    fn serialize_g1_point(point: &ark_bn254::G1Affine) -> [String; 2] {
        if let Some((x, y)) = point.xy() {
            [
                Self::fq_to_hex(x),
                Self::fq_to_hex(y),
            ]
        } else {
            ["0x0".to_string(), "0x0".to_string()]
        }
    }
    
    fn serialize_g2_point(point: &ark_bn254::G2Affine) -> [[String; 2]; 2] {
        if let Some((x, y)) = point.xy() {
            [
                [
                    Self::fq_to_hex(&x.c0),
                    Self::fq_to_hex(&x.c1),
                ],
                [
                    Self::fq_to_hex(&y.c0),
                    Self::fq_to_hex(&y.c1),
                ],
            ]
        } else {
            [["0x0".to_string(), "0x0".to_string()], ["0x0".to_string(), "0x0".to_string()]]
        }
    }
    
    fn fq_to_hex(field: &ark_bn254::Fq) -> String {
        let bigint = field.into_bigint();
        let bytes = bigint.to_bytes_le();
        format!("0x{}", hex::encode(bytes))
    }
}

/// 简化的性能指标收集器
struct PerformanceCollector {
    task_id: usize,
    start_time: Instant,
    
    // 客户端工作时间（保留）
    witness_generation_time_ms: f64,
    witness_secret_sharing_time_ms: f64,
    
    // MPC时间（取最慢的那一方）
    mpc_preprocessing_time_ms: f64,
    mpc_r1cs_to_qap_ms: f64,
    mpc_total_time_ms: f64,           // 最慢方的总MPC时间
    mpc_h_computation_ms: f64,        // 最慢方的H计算时间
    mpc_a_computation_ms: f64,
    mpc_b_g1_computation_ms: f64,
    mpc_b_g2_computation_ms: f64,
    mpc_c_computation_ms: f64,
    mpc_reconstruction_time_ms: f64,
    
    // 其他指标
    circuit_building_time_ms: f64,
    serialization_time_ms: f64,
    verification_time_ms: f64,
}

impl PerformanceCollector {
    fn new(task_id: usize) -> Self {
        Self {
            task_id,
            start_time: Instant::now(),
            witness_generation_time_ms: 0.0,
            witness_secret_sharing_time_ms: 0.0,
            mpc_preprocessing_time_ms: 0.0,
            mpc_r1cs_to_qap_ms: 0.0,
            mpc_total_time_ms: 0.0,
            mpc_h_computation_ms: 0.0,
            mpc_a_computation_ms: 0.0,
            mpc_b_g1_computation_ms: 0.0,
            mpc_b_g2_computation_ms: 0.0,
            mpc_c_computation_ms: 0.0,
            mpc_reconstruction_time_ms: 0.0,
            circuit_building_time_ms: 0.0,
            serialization_time_ms: 0.0,
            verification_time_ms: 0.0,
        }
    }

    // 客户端时间记录（保持不变）
    fn record_witness_generation(&mut self, duration_ms: f64) {
        self.witness_generation_time_ms = duration_ms;
    }
    
    fn record_witness_secret_sharing(&mut self, duration_ms: f64) {
        self.witness_secret_sharing_time_ms = duration_ms;
    }
    
    fn record_circuit_building(&mut self, duration_ms: f64) {
        self.circuit_building_time_ms = duration_ms;
    }
    
    fn record_mpc_preprocessing(&mut self, duration_ms: f64) {
        self.mpc_preprocessing_time_ms = duration_ms;
    }
    
    fn record_mpc_r1cs_to_qap(&mut self, duration_ms: f64) {
        self.mpc_r1cs_to_qap_ms = duration_ms;
    }
    
    fn record_mpc_reconstruction(&mut self, duration_ms: f64) {
        self.mpc_reconstruction_time_ms = duration_ms;
    }
    
    // 新增：选择最慢方的MPC时间
    fn record_slowest_mpc_metrics(&mut self, all_party_metrics: &[MpcDetailedMetrics]) {
        // 找到总时间最长的那一方
        let slowest_party = all_party_metrics
            .iter()
            .max_by(|a, b| a.total_pure_computation_ms.partial_cmp(&b.total_pure_computation_ms).unwrap())
            .unwrap();
        
        // 记录最慢方的所有时间
        self.mpc_total_time_ms = slowest_party.total_pure_computation_ms;
        self.mpc_h_computation_ms = slowest_party.h_computation_ms;
        self.mpc_a_computation_ms = slowest_party.a_computation_ms;
        self.mpc_b_g1_computation_ms = slowest_party.b_g1_computation_ms;
        self.mpc_b_g2_computation_ms = slowest_party.b_g2_computation_ms;
        self.mpc_c_computation_ms = slowest_party.c_computation_ms;
    }
    
    fn record_serialization(&mut self, duration_ms: f64) {
        self.serialization_time_ms = duration_ms;
    }
    
    fn record_verification(&mut self, duration_ms: f64) {
        self.verification_time_ms = duration_ms;
    }

    fn calculate_client_total_time(&self) -> f64 {
        self.witness_generation_time_ms + self.witness_secret_sharing_time_ms
    }

    fn save_metrics(&self, circuit_info: &CircuitInfo, proof_size: usize, commitment_size: u64) {
        let task_csv = CSVLogger::new(&format!("logs/metrics/task_{}_metrics.csv", self.task_id));
        
        let total_time = self.start_time.elapsed().as_millis() as f64;
        let client_total_time = self.calculate_client_total_time();
        
        let metrics = vec![
            // 基本任务信息
            ("task_id".to_string(), self.task_id.to_string()),
            
            // 客户端工作指标（保留）
            ("witness_generation_ms".to_string(), self.witness_generation_time_ms.to_string()),
            ("witness_secret_sharing_ms".to_string(), self.witness_secret_sharing_time_ms.to_string()),
            ("r1cs_to_qap_ms".to_string(), self.mpc_r1cs_to_qap_ms.to_string()),
            ("client_total_time_ms".to_string(), client_total_time.to_string()),
            
            // MPC时间（最慢方）
            ("mpc_preprocessing_ms".to_string(), self.mpc_preprocessing_time_ms.to_string()),
            ("mpc_total_time_ms".to_string(), self.mpc_total_time_ms.to_string()),
            ("mpc_h_computation_ms".to_string(), self.mpc_h_computation_ms.to_string()),
            ("mpc_a_computation_ms".to_string(), self.mpc_a_computation_ms.to_string()),
            ("mpc_b_g1_computation_ms".to_string(), self.mpc_b_g1_computation_ms.to_string()),
            ("mpc_b_g2_computation_ms".to_string(), self.mpc_b_g2_computation_ms.to_string()),
            ("mpc_c_computation_ms".to_string(), self.mpc_c_computation_ms.to_string()),
            ("mpc_reconstruction_ms".to_string(), self.mpc_reconstruction_time_ms.to_string()),
            
            // 其他指标
            ("circuit_building_ms".to_string(), self.circuit_building_time_ms.to_string()),
            ("serialization_ms".to_string(), self.serialization_time_ms.to_string()),
            ("verification_ms".to_string(), self.verification_time_ms.to_string()),
            ("total_task_time_ms".to_string(), total_time.to_string()),
            ("proof_size_bytes".to_string(), proof_size.to_string()),
            ("commitment_size_bytes".to_string(), commitment_size.to_string()),
            
            // 电路信息
            ("constraint_count".to_string(), circuit_info.num_constraints.to_string()),
            ("variable_count".to_string(), circuit_info.num_variables.to_string()),
            ("public_inputs_count".to_string(), circuit_info.public_inputs_count.to_string()),
            ("qap_size_bytes".to_string(), circuit_info.qap_size_bytes.to_string()),
            ("qap_domain_size".to_string(), circuit_info.qap_domain_size.to_string()),
        ];

        task_csv.safe_write_metrics(&metrics.iter().map(|(k, v)| (k.as_str(), v.clone())).collect::<Vec<_>>());
    }
}

struct CircuitInfo {
    num_constraints: usize,
    num_variables: usize,
    public_inputs_count: usize,
    qap_size_bytes: usize,
    qap_domain_size: usize,
}

/// MPC详细性能指标
#[derive(Debug, Clone)]
struct MpcDetailedMetrics {
    h_computation_ms: f64,
    a_computation_ms: f64,
    b_g1_computation_ms: f64,
    b_g2_computation_ms: f64,
    c_computation_ms: f64,
    total_pure_computation_ms: f64,  // 所有MSM操作的总时间
}

impl MpcDetailedMetrics {
    fn new() -> Self {
        Self {
            h_computation_ms: 0.0,
            a_computation_ms: 0.0,
            b_g1_computation_ms: 0.0,
            b_g2_computation_ms: 0.0,
            c_computation_ms: 0.0,
            total_pure_computation_ms: 0.0,
        }
    }
    
    // 辅助方法：获取最慢的操作时间
    fn get_bottleneck_operation(&self) -> (&str, f64) {
        let operations = [
            ("H computation", self.h_computation_ms),
            ("A computation", self.a_computation_ms),
            ("B(G1) computation", self.b_g1_computation_ms),
            ("B(G2) computation", self.b_g2_computation_ms),
            ("C computation", self.c_computation_ms),
        ];
        
        operations
            .iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .map(|(name, time)| (*name, *time))
            .unwrap_or(("Unknown", 0.0))
    }
}
// ======================= 缓存和序列化函数 =======================

fn should_use_cache(task_id: usize) -> bool {
    task_id > 0 && Path::new("proof_data/cache/ready.flag").exists()
}

fn save_cache(pk: &ProvingKey<Bn254>, vk: &VerifyingKey<Bn254>) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("proof_data/cache")?;
    
    // Stream directly to disk to avoid holding an extra large serialized buffer.
    let pk_file = File::create("proof_data/cache/proving_key.bin")?;
    let mut pk_writer = BufWriter::new(pk_file);
    pk.serialize_compressed(&mut pk_writer)?;
    pk_writer.flush()?;
    
    let vk_file = File::create("proof_data/cache/verifying_key.bin")?;
    let mut vk_writer = BufWriter::new(vk_file);
    vk.serialize_compressed(&mut vk_writer)?;
    vk_writer.flush()?;
    
    // 创建完成标志
    fs::write("proof_data/cache/ready.flag", "ready")?;
    
    println!("💾 缓存已保存到 cache/ 目录");
    Ok(())
}

fn load_cache() -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), Box<dyn std::error::Error>> {
    let pk_file = File::open("proof_data/cache/proving_key.bin")?;
    let mut pk_reader = BufReader::new(pk_file);
    let pk = ProvingKey::deserialize_compressed(&mut pk_reader)?;

    let vk_file = File::open("proof_data/cache/verifying_key.bin")?;
    let mut vk_reader = BufReader::new(vk_file);
    let vk = VerifyingKey::deserialize_compressed(&mut vk_reader)?;
    
    println!("📂 缓存加载成功");
    Ok((pk, vk))
}

fn load_vk_cache() -> Result<VerifyingKey<Bn254>, Box<dyn std::error::Error>> {
    let vk_file = File::open("proof_data/cache/verifying_key.bin")?;
    let mut vk_reader = BufReader::new(vk_file);
    let vk = VerifyingKey::deserialize_compressed(&mut vk_reader)?;

    println!("📂 验证密钥缓存加载成功");
    Ok(vk)
}

// 将椭圆曲线点转换为hex字符串
fn g1_point_to_hex(point: &G1Affine) -> [String; 2] {
    if point.is_zero() {
        ["0x0".to_string(), "0x0".to_string()]
    } else if let Some((x, y)) = point.xy() {
        [
            format!("0x{}", hex::encode(x.into_bigint().to_bytes_le())),
            format!("0x{}", hex::encode(y.into_bigint().to_bytes_le()))
        ]
    } else {
        ["0x0".to_string(), "0x0".to_string()]
    }
}

fn g2_point_to_hex(point: &G2Affine) -> [[String; 2]; 2] {
    if point.is_zero() {
        [["0x0".to_string(), "0x0".to_string()], ["0x0".to_string(), "0x0".to_string()]]
    } else if let Some((x, y)) = point.xy() {
        [
            [
                format!("0x{}", hex::encode(x.c0.into_bigint().to_bytes_le())),
                format!("0x{}", hex::encode(x.c1.into_bigint().to_bytes_le()))
            ],
            [
                format!("0x{}", hex::encode(y.c0.into_bigint().to_bytes_le())),
                format!("0x{}", hex::encode(y.c1.into_bigint().to_bytes_le()))
            ]
        ]
    } else {
        [["0x0".to_string(), "0x0".to_string()], ["0x0".to_string(), "0x0".to_string()]]
    }
}

// 从hex字符串转换回椭圆曲线点
fn hex_to_g1_point(hex_coords: &[String; 2]) -> Result<G1Affine, Box<dyn std::error::Error>> {
    if hex_coords[0] == "0x0" && hex_coords[1] == "0x0" {
        return Ok(G1Affine::zero());
    }
    
    // 移除0x前缀
    let x_hex = hex_coords[0].trim_start_matches("0x");
    let y_hex = hex_coords[1].trim_start_matches("0x");
    
    // 解码hex字符串
    let x_bytes = hex::decode(x_hex)?;
    let y_bytes = hex::decode(y_hex)?;
    
    // 从字节数组重建字段元素
    let x = Fq::from_le_bytes_mod_order(&x_bytes);
    let y = Fq::from_le_bytes_mod_order(&y_bytes);
    
    // 重建椭圆曲线点
    let point = G1Affine::new_unchecked(x, y);
    
    // 验证点是否在曲线上
    if !point.is_on_curve() {
        return Err("Point not on curve".into());
    }
    
    Ok(point)
}

fn hex_to_g2_point(hex_coords: &[[String; 2]; 2]) -> Result<G2Affine, Box<dyn std::error::Error>> {
    if hex_coords[0][0] == "0x0" && hex_coords[0][1] == "0x0" && 
       hex_coords[1][0] == "0x0" && hex_coords[1][1] == "0x0" {
        return Ok(G2Affine::zero());
    }
    
    // 解析x坐标 (Fq2)
    let x_c0_hex = hex_coords[0][0].trim_start_matches("0x");
    let x_c1_hex = hex_coords[0][1].trim_start_matches("0x");
    let x_c0_bytes = hex::decode(x_c0_hex)?;
    let x_c1_bytes = hex::decode(x_c1_hex)?;
    let x_c0 = Fq::from_le_bytes_mod_order(&x_c0_bytes);
    let x_c1 = Fq::from_le_bytes_mod_order(&x_c1_bytes);
    let x = Fq2::new(x_c0, x_c1);
    
    // 解析y坐标 (Fq2)
    let y_c0_hex = hex_coords[1][0].trim_start_matches("0x");
    let y_c1_hex = hex_coords[1][1].trim_start_matches("0x");
    let y_c0_bytes = hex::decode(y_c0_hex)?;
    let y_c1_bytes = hex::decode(y_c1_hex)?;
    let y_c0 = Fq::from_le_bytes_mod_order(&y_c0_bytes);
    let y_c1 = Fq::from_le_bytes_mod_order(&y_c1_bytes);
    let y = Fq2::new(y_c0, y_c1);
    
    // 重建椭圆曲线点
    let point = G2Affine::new_unchecked(x, y);
    
    // 验证点是否在曲线上
    if !point.is_on_curve() {
        return Err("G2 point not on curve".into());
    }
    
    Ok(point)
}

fn save_crs_shares_cache(crs_shares: &[PackedProvingKeyShare<Bn254>], cache_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("proof_data/cache")?;

    let cache_path = format!("proof_data/cache/crs_shares_{}.bin", cache_key);
    let file = File::create(&cache_path)?;
    let mut writer = BufWriter::new(file);
    crs_shares.serialize_compressed(&mut writer)?;
    writer.flush()?;
    fs::write(format!("proof_data/cache/crs_ready_{}.flag", cache_key), "ready")?;

    let file_size = fs::metadata(&cache_path)?.len();
    println!("💾 CRS分享缓存已保存 ({}, {:.1} MB)", cache_key, file_size as f64 / (1024.0 * 1024.0));
    Ok(())
}

fn load_crs_shares_cache(cache_key: &str) -> Result<Vec<PackedProvingKeyShare<Bn254>>, Box<dyn std::error::Error>> {
    let cache_path = format!("proof_data/cache/crs_shares_{}.bin", cache_key);

    if Path::new(&cache_path).exists() {
        let file_size = fs::metadata(&cache_path)?.len();
        let file = File::open(&cache_path)?;
        let mut reader = BufReader::new(file);
        let crs_shares = Vec::<PackedProvingKeyShare<Bn254>>::deserialize_compressed(&mut reader)?;
        println!("📂 CRS分享缓存加载成功 ({}, {} shares, {:.1} MB)", cache_key, crs_shares.len(), file_size as f64 / (1024.0 * 1024.0));
        return Ok(crs_shares);
    }

    let json_path = format!("proof_data/cache/crs_shares_{}.json", cache_key);
    let json_str = fs::read_to_string(&json_path)?;
    let json_data: Vec<Value> = serde_json::from_str(&json_str)?;

    let mut crs_shares = Vec::new();

    for (i, share_data) in json_data.iter().enumerate() {
        // 解析G1点数组
        let s: Result<Vec<G1Affine>, _> = share_data["s"]
            .as_array()
            .ok_or("Missing s field")?
            .iter()
            .map(|point_json| {
                let coords = [
                    point_json[0].as_str().unwrap_or("0x0").to_string(),
                    point_json[1].as_str().unwrap_or("0x0").to_string()
                ];
                hex_to_g1_point(&coords)
            })
            .collect();
        let s = s.map_err(|e| format!("Failed to parse s array for share {}: {}", i, e))?;
        
        let h: Result<Vec<G1Affine>, _> = share_data["h"]
            .as_array()
            .ok_or("Missing h field")?
            .iter()
            .map(|point_json| {
                let coords = [
                    point_json[0].as_str().unwrap_or("0x0").to_string(),
                    point_json[1].as_str().unwrap_or("0x0").to_string()
                ];
                hex_to_g1_point(&coords)
            })
            .collect();
        let h = h.map_err(|e| format!("Failed to parse h array for share {}: {}", i, e))?;
        
        let w: Result<Vec<G1Affine>, _> = share_data["w"]
            .as_array()
            .ok_or("Missing w field")?
            .iter()
            .map(|point_json| {
                let coords = [
                    point_json[0].as_str().unwrap_or("0x0").to_string(),
                    point_json[1].as_str().unwrap_or("0x0").to_string()
                ];
                hex_to_g1_point(&coords)
            })
            .collect();
        let w = w.map_err(|e| format!("Failed to parse w array for share {}: {}", i, e))?;
        
        let u: Result<Vec<G1Affine>, _> = share_data["u"]
            .as_array()
            .ok_or("Missing u field")?
            .iter()
            .map(|point_json| {
                let coords = [
                    point_json[0].as_str().unwrap_or("0x0").to_string(),
                    point_json[1].as_str().unwrap_or("0x0").to_string()
                ];
                hex_to_g1_point(&coords)
            })
            .collect();
        let u = u.map_err(|e| format!("Failed to parse u array for share {}: {}", i, e))?;
        
        // 解析G2点数组
        let v: Result<Vec<G2Affine>, _> = share_data["v"]
            .as_array()
            .ok_or("Missing v field")?
            .iter()
            .map(|point_json| {
                let coords = [
                    [
                        point_json[0][0].as_str().unwrap_or("0x0").to_string(),
                        point_json[0][1].as_str().unwrap_or("0x0").to_string()
                    ],
                    [
                        point_json[1][0].as_str().unwrap_or("0x0").to_string(),
                        point_json[1][1].as_str().unwrap_or("0x0").to_string()
                    ]
                ];
                hex_to_g2_point(&coords)
            })
            .collect();
        let v = v.map_err(|e| format!("Failed to parse v array for share {}: {}", i, e))?;
        
        // 解析单个椭圆曲线点
        let alpha_g1_coords = [
            share_data["alpha_g1"][0].as_str().unwrap_or("0x0").to_string(),
            share_data["alpha_g1"][1].as_str().unwrap_or("0x0").to_string()
        ];
        let alpha_g1 = hex_to_g1_point(&alpha_g1_coords)?;
        
        let beta_g1_coords = [
            share_data["beta_g1"][0].as_str().unwrap_or("0x0").to_string(),
            share_data["beta_g1"][1].as_str().unwrap_or("0x0").to_string()
        ];
        let beta_g1 = hex_to_g1_point(&beta_g1_coords)?;
        
        let beta_g2_coords = [
            [
                share_data["beta_g2"][0][0].as_str().unwrap_or("0x0").to_string(),
                share_data["beta_g2"][0][1].as_str().unwrap_or("0x0").to_string()
            ],
            [
                share_data["beta_g2"][1][0].as_str().unwrap_or("0x0").to_string(),
                share_data["beta_g2"][1][1].as_str().unwrap_or("0x0").to_string()
            ]
        ];
        let beta_g2 = hex_to_g2_point(&beta_g2_coords)?;
        
        let delta_g1_coords = [
            share_data["delta_g1"][0].as_str().unwrap_or("0x0").to_string(),
            share_data["delta_g1"][1].as_str().unwrap_or("0x0").to_string()
        ];
        let delta_g1 = hex_to_g1_point(&delta_g1_coords)?;
        
        let delta_g2_coords = [
            [
                share_data["delta_g2"][0][0].as_str().unwrap_or("0x0").to_string(),
                share_data["delta_g2"][0][1].as_str().unwrap_or("0x0").to_string()
            ],
            [
                share_data["delta_g2"][1][0].as_str().unwrap_or("0x0").to_string(),
                share_data["delta_g2"][1][1].as_str().unwrap_or("0x0").to_string()
            ]
        ];
        let delta_g2 = hex_to_g2_point(&delta_g2_coords)?;
        
        let a_query0_coords = [
            share_data["a_query0"][0].as_str().unwrap_or("0x0").to_string(),
            share_data["a_query0"][1].as_str().unwrap_or("0x0").to_string()
        ];
        let a_query0 = hex_to_g1_point(&a_query0_coords)?;
        
        let b_g1_query0_coords = [
            share_data["b_g1_query0"][0].as_str().unwrap_or("0x0").to_string(),
            share_data["b_g1_query0"][1].as_str().unwrap_or("0x0").to_string()
        ];
        let b_g1_query0 = hex_to_g1_point(&b_g1_query0_coords)?;
        
        let b_g2_query0_coords = [
            [
                share_data["b_g2_query0"][0][0].as_str().unwrap_or("0x0").to_string(),
                share_data["b_g2_query0"][0][1].as_str().unwrap_or("0x0").to_string()
            ],
            [
                share_data["b_g2_query0"][1][0].as_str().unwrap_or("0x0").to_string(),
                share_data["b_g2_query0"][1][1].as_str().unwrap_or("0x0").to_string()
            ]
        ];
        let b_g2_query0 = hex_to_g2_point(&b_g2_query0_coords)?;
        
        // 重建PackedProvingKeyShare
        let crs_share = PackedProvingKeyShare {
            s,
            h,
            w,
            u,
            v,
            alpha_g1,
            beta_g1,
            beta_g2,
            delta_g1,
            delta_g2,
            a_query0,
            b_g1_query0,
            b_g2_query0,
        };
        
        crs_shares.push(crs_share);
    }
    
    println!("📂 CRS分享JSON缓存加载成功 ({}, {} shares, {:.1} MB)", cache_key, crs_shares.len(), json_str.len() as f64 / (1024.0 * 1024.0));
    Ok(crs_shares)
}

// 检查缓存是否存在
fn should_use_crs_cache(task_id: usize, cache_key: &str) -> bool {
    task_id > 0 && Path::new(&format!("proof_data/cache/crs_ready_{}.flag", cache_key)).exists()
}

/// 分布式 MPC 证明生成函数（使用arkworks标准计时）
#[allow(clippy::too_many_arguments)]
async fn distributed_mpc_proof_generation<E, Net>(
    pp: &PackedSharingParams<E::ScalarField>,
    crs_share: &PackedProvingKeyShare<E>,
    qap_share: qap::PackedQAPShare<
        E::ScalarField,
        Radix2EvaluationDomain<E::ScalarField>,
    >,
    a_share: &[E::ScalarField],
    ax_share: &[E::ScalarField],
    r_share: E::ScalarField,
    s_share: E::ScalarField,
    fft_mask: &[FftMask<E::ScalarField>; 6],
    f_degred_mask: &DegRedMask<E::ScalarField, E::ScalarField>,
    g1_msm_mask: &[MsmMask<E::G1>; 4],
    g2_msm_mask: &MsmMask<E::G2>,
    local_completion_barrier: Arc<Barrier>,
    net: &Net,
) -> (E::G1, E::G2, E::G1, MpcDetailedMetrics)
where
    E: Pairing,
    Net: MpcNet,
{
    let mut metrics = MpcDetailedMetrics::new();
    
    // 使用arkworks标准计时宏，正确的用法
    let mpc_section = start_timer!(|| "MPC MSM operations");
    
    // 1. H计算计时
    let compute_h = start_timer!(|| "H computation");
    let h_share = ext_wit::circom_h(qap_share, fft_mask, f_degred_mask, pp, &net)
        .await
        .unwrap();
    end_timer!(compute_h);
    metrics.h_computation_ms = compute_h.time.elapsed().as_millis() as f64;
    
    // 2. A计算计时
    let compute_a = start_timer!(|| "A computation");
    let pi_a_share = groth16::prove::A::<E> {
        L: crs_share.a_query0,
        N: crs_share.delta_g1,
        AG1: crs_share.alpha_g1,
        r: r_share,
        pp,
        S: &crs_share.s,
        a: a_share,
    }
    .compute(&g1_msm_mask[0], net, MultiplexedStreamID::Zero)
    .await
    .unwrap();
    end_timer!(compute_a);
    metrics.a_computation_ms = compute_a.time.elapsed().as_millis() as f64;

    // 3. B(G1)计算计时
    let compute_b_g1 = start_timer!(|| "Compute B in G1");
    let pi_b_g1_share: E::G1 = groth16::prove::BInG1::<E> {
        Z: crs_share.b_g1_query0,
        K: crs_share.delta_g1,
        BG1: crs_share.beta_g1,
        r: r_share,
        s: s_share,
        pp,
        H: &crs_share.h,
        a: a_share,
    }
    .compute(&g1_msm_mask[1], net, MultiplexedStreamID::Zero)
    .await
    .unwrap();
    end_timer!(compute_b_g1);
    metrics.b_g1_computation_ms = compute_b_g1.time.elapsed().as_millis() as f64;
    
    // 4. B(G2)计算计时
    let compute_b_g2 = start_timer!(|| "Compute B in G2");
    let pi_b_g2_share: E::G2 = groth16::prove::BInG2::<E> {
        Z: crs_share.b_g2_query0,
        K: crs_share.delta_g2,
        BG2: crs_share.beta_g2,
        s: s_share,
        pp,
        V: &crs_share.v,
        a: a_share,
    }
    .compute(g2_msm_mask, net, MultiplexedStreamID::Zero)
    .await
    .unwrap();
    end_timer!(compute_b_g2);
    metrics.b_g2_computation_ms = compute_b_g2.time.elapsed().as_millis() as f64;

    // 5. C计算计时
    let compute_c = start_timer!(|| "Compute C");
    let pi_c_share = match (groth16::prove::C::<E> {
        W: &crs_share.w,
        U: &crs_share.u,
        A: pi_a_share,
        B: pi_b_g1_share,
        M: crs_share.delta_g1,
        r: r_share,
        s: s_share,
        pp,
        H: &crs_share.h,
        a: a_share,
        ax: ax_share,
        h: &h_share,
    })
    .compute(&[g1_msm_mask[2].clone(), g1_msm_mask[3].clone()], net)
    .await {
        Ok(result) => result,
        Err(e) => {
            end_timer!(compute_c);
            panic!("C computation failed for party {}: {:?}", net.party_id(), e);
        }
    };
    end_timer!(compute_c);
    metrics.c_computation_ms = compute_c.time.elapsed().as_millis() as f64;

    local_completion_barrier.wait().await;

    end_timer!(mpc_section);
    
    // 计算总的纯计算时间
    metrics.total_pure_computation_ms = mpc_section.time.elapsed().as_millis() as f64;

    (pi_a_share, pi_b_g2_share, pi_c_share, metrics)
}

fn pack_from_witness<E: Pairing>(
    pp: &PackedSharingParams<E::ScalarField>,
    full_assignment: Vec<E::ScalarField>,
) -> Vec<Vec<E::ScalarField>> {
    let packed_assignments = cfg_chunks!(full_assignment, pp.l)
        .map(|chunk| {
            let rng = &mut ark_std::rand::rngs::StdRng::from_seed([44u8; 32]);
            let secrets = if chunk.len() < pp.l {
                let mut secrets = chunk.to_vec();
                secrets.resize(pp.l, E::ScalarField::zero());
                secrets
            } else {
                chunk.to_vec()
            };
            pp.pack(secrets, rng)
        })
        .collect::<Vec<_>>();

    cfg_into_iter!(0..pp.n)
        .map(|i| {
            cfg_into_iter!(0..packed_assignments.len())
                .map(|j| packed_assignments[j][i])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 9 {
        eprintln!("Usage: {} <party_id> <task_id> <network_config_dir> <l> <t> <m> <r1cs_file> <witness_file> [expected_match] [n]", args[0]);
        eprintln!("  task_id: Unique identifier for this proof generation task");
        eprintln!("  network_config_dir: Directory containing network configuration");
        eprintln!("  l: MPC packing parameter");
        eprintln!("  t: MPC threshold parameter"); 
        eprintln!("  m: MPC security parameter");
        eprintln!("  r1cs_file: Path to R1CS circuit file");
        eprintln!("  witness_file: Path to witness JSON file");
        std::process::exit(1);
    }

    // 解析命令行参数
    let party_id: usize = args[1].parse().expect("Invalid party_id");
    let task_id: usize = args[2].parse().expect("Invalid task_id");
    let _network_config_dir = &args[3];
    let l: usize = args[4].parse().expect("Invalid l");
    let t_arg: usize = args[5].parse().expect("Invalid t");
    let _m: usize = args[6].parse().expect("Invalid m");
    let r1cs_file = &args[7];
    let witness_file = &args[8];
    let expected_match: i32 = args
        .get(9)
        .map(|s| s.parse().expect("Invalid expected_match"))
        .unwrap_or(1);
    let n_arg: Option<usize> = args
        .get(10)
        .map(|s| s.parse().expect("Invalid n"));

    // 初始化性能收集器
    let mut perf_collector = PerformanceCollector::new(task_id);
    
    // 用户交互信息
    println!("🚀 Proof Generation Task {} starting...", party_id);
    
    // 1. 电路配置加载
    let witness = match Witness::from_file(witness_file) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("❌ party {} failed to load witness file: {}", party_id, e);
            std::process::exit(1);
        }
    };

    let wasm_file = r1cs_file.replace(".r1cs", "_js");
    let circuit_name = std::path::Path::new(r1cs_file)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("circuit");
    let wasm_path = format!("{}/{}.wasm", wasm_file, circuit_name);

    let cfg = CircomConfig::<Bn254>::new(&wasm_path, r1cs_file)
        .unwrap_or_else(|e| {
            eprintln!("❌ party {} circuit configuration failed: {}", task_id, e);
            std::process::exit(1);
        });

    // 2. 客户端工作：witness生成
    let witness_gen_start = Instant::now();
    let msg_array = witness.password_to_bytes(20);
    let k_value = witness.k_to_int();

    let mut builder = CircomBuilder::new(cfg.clone());
    // 添加输入
    for &byte_val in msg_array.iter() {
        builder.push_input("msg", byte_val as i32);
    }
    builder.push_input("k", k_value);
    builder.push_input("expected_match", expected_match);

    let circom = builder.clone().build().unwrap();
    let public_inputs = circom.get_public_inputs().unwrap();
    let full_assignment = circom.witness.clone().unwrap();
    perf_collector.record_witness_generation(witness_gen_start.elapsed().as_millis() as f64);

    // 3. 服务器工作：电路构建和可信设置
    let trusted_setup_start = Instant::now();
    let rng = &mut ark_std::rand::rngs::StdRng::from_seed([42u8; 32]);
    let pp = match n_arg {
        Some(n) => PackedSharingParams::new_with_params(n, l, t_arg),
        None => PackedSharingParams::new(l),
    };
    let crs_cache_key = format!("n{}_l{}_t{}", pp.n, pp.l, pp.t);
    let crs_cache_available = should_use_crs_cache(task_id, &crs_cache_key);

    // 创建用于setup的builder，使用dummy输入
    let mut setup_builder = CircomBuilder::new(cfg.clone());
    // 用dummy值进行setup（不需要真实的witness数据）
    for _ in 0..20 {
        setup_builder.push_input("msg", 0i32);
    }
    setup_builder.push_input("k", 0i32);
    setup_builder.push_input("expected_match", 0i32);

    let (pk, vk) = if crs_cache_available && should_use_cache(task_id) {
        println!("🚀 CRS分享缓存已存在，仅加载验证密钥，跳过ProvingKey加载");
        match load_vk_cache() {
            Ok(vk) => (None, vk),
            Err(e) => {
                println!("⚠️ 验证密钥缓存加载失败: {}，回退为加载完整可信设置缓存...", e);
                let (pk, vk) = load_cache().unwrap_or_else(|cache_e| {
                    println!("⚠️ 完整缓存加载失败: {}，重新计算...", cache_e);
                    let mut setup_rng = ark_std::rand::rngs::StdRng::from_seed([42u8; 32]);
                    let setup_circuit = setup_builder.setup();
                    Groth16::<Bn254, CircomReduction>::circuit_specific_setup(setup_circuit, &mut setup_rng).unwrap()
                });
                (Some(pk), vk)
            }
        }
    } else if should_use_cache(task_id) {
        println!("🚀 加载缓存的可信设置...");
        match load_cache() {
            Ok((pk, vk)) => {
                println!("✅ 缓存加载成功！");
                (Some(pk), vk)
            },
            Err(e) => {
                println!("⚠️ 缓存加载失败: {}，重新计算...", e);
                // 缓存加载失败，重新计算
                let mut setup_rng = ark_std::rand::rngs::StdRng::from_seed([42u8; 32]);
                let setup_circuit = setup_builder.setup(); // 使用setup_builder而不是builder
                let (pk, vk) = Groth16::<Bn254, CircomReduction>::circuit_specific_setup(setup_circuit, &mut setup_rng).unwrap();
                (Some(pk), vk)
            }
        }
    } else {
        println!("🔧 执行可信设置...");
        let mut setup_rng = ark_std::rand::rngs::StdRng::from_seed([42u8; 32]);
        
        let circuit = setup_builder.setup();
        let (pk, vk) = Groth16::<Bn254, CircomReduction>::circuit_specific_setup(circuit, &mut setup_rng).unwrap();
        
        // 仅task_id=0保存缓存
        if task_id == 0 {
            if let Err(e) = save_cache(&pk, &vk) {
                eprintln!("⚠️ 保存缓存失败: {}", e);
            } else {
                println!("✅ 可信设置已缓存，后续任务将复用");
            }
        }
        (Some(pk), vk)
    };
    perf_collector.record_circuit_building(trusted_setup_start.elapsed().as_millis() as f64);

    // 验证约束并收集电路信息（移到客户端工作）
    let cs = ConstraintSystem::<Bn254Fr>::new_ref();
    circom.generate_constraints(cs.clone()).unwrap();
    if !cs.is_satisfied().unwrap_or(false) {
        let unsatisfied = cs
            .which_is_unsatisfied()
            .ok()
            .flatten()
            .unwrap_or_else(|| "unknown constraint".to_string());
        panic!(
            "Circom witness does not satisfy the R1CS constraints before MPC proving: {}",
            unsatisfied
        );
    }

    let matrices = cs.to_matrices().unwrap();
    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    // 4. 客户端工作：R1CS to QAP（现在算作客户端工作）
    let mpc_r1cs_to_qap_start = Instant::now();
    let qap = qap::<Bn254Fr, Radix2EvaluationDomain<_>>(&matrices, &full_assignment)
        .unwrap();
    let r1cs_to_qap_time = mpc_r1cs_to_qap_start.elapsed().as_millis() as f64;
    perf_collector.record_mpc_r1cs_to_qap(r1cs_to_qap_time);

    // 收集电路信息
    let qap_size_bytes = {
        use ark_serialize::CanonicalSerialize;
        let mut total_size = 0;
        
        let mut buffer = Vec::new();
        qap.a.serialize_compressed(&mut buffer).unwrap();
        total_size += buffer.len();
        
        buffer.clear();
        qap.b.serialize_compressed(&mut buffer).unwrap();
        total_size += buffer.len();
        
        buffer.clear();
        qap.c.serialize_compressed(&mut buffer).unwrap();
        total_size += buffer.len();
        
        buffer.clear();
        qap.domain.serialize_compressed(&mut buffer).unwrap();
        total_size += buffer.len();
        
        total_size
    };

    let circuit_info = CircuitInfo {
        num_constraints,
        num_variables: matrices.num_witness_variables + num_inputs,
        public_inputs_count: public_inputs.len(),
        qap_size_bytes,
        qap_domain_size: qap.domain.size(),
    };

    // 写入电路信息（仅task 0执行一次）
    if task_id == 0 {
        let circuit_csv = CSVLogger::new("logs/metrics/circuit_info.csv");
        let circuit_metrics = vec![
            ("constraint_count", circuit_info.num_constraints.to_string()),
            ("variable_count", circuit_info.num_variables.to_string()),
            ("public_inputs_count", circuit_info.public_inputs_count.to_string()),
            ("qap_size_bytes", circuit_info.qap_size_bytes.to_string()),
            ("qap_domain_size", circuit_info.qap_domain_size.to_string()),
        ];
        circuit_csv.safe_write_metrics(&circuit_metrics.iter().map(|(k, v)| (*k, v.clone())).collect::<Vec<_>>());
    }

    // 6. MPC阶段1：预处理
    let mpc_preprocessing_start = Instant::now();
    let r = Bn254Fr::rand(rng);
    let s = Bn254Fr::rand(rng);

    println!("🔧 MPC Preprocessing - System-wide cost analysis:");
    println!("  ├─ Number of parties: {}", pp.n);
    println!("  ├─ Packing l: {}", pp.l);
    println!("  ├─ Effective threshold t from PackedSharingParams: {}", pp.t);
    println!("  ├─ CLI threshold argument: {} (currently informational)", t_arg);
    println!("  ├─ zkSaaS bound requires t < n/2 - l: {} < {}", pp.t, pp.n / 2 - pp.l);
    if pp.t >= pp.n / 2 - pp.l {
        println!("  ⚠️  Current PackedSharingParams do NOT satisfy the strict zkSaaS bound t < n/2 - l");
    }

    // Dealer工作
    let dealer_step_start = Instant::now();
    let r_shares = pp.pack(vec![r; pp.n], rng);
    println!(
        "  ├─ Dealer pack r: {:.2}s",
        dealer_step_start.elapsed().as_secs_f64()
    );
    let dealer_step_start = Instant::now();
    let s_shares = pp.pack(vec![s; pp.n], rng);
    println!(
        "  ├─ Dealer pack s: {:.2}s",
        dealer_step_start.elapsed().as_secs_f64()
    );
    let dealer_step_start = Instant::now();
    let qap_shares = qap.pss(&pp);
    drop(qap);
    drop(matrices);
    println!(
        "  ├─ Dealer pack qap: {:.2}s",
        dealer_step_start.elapsed().as_secs_f64()
    );
    //let crs_shares = PackedProvingKeyShare::<Bn254>::pack_from_arkworks_proving_key(&pk, pp);
    let crs_shares = if should_use_crs_cache(task_id, &crs_cache_key) {
        println!("🚀 加载缓存的CRS分享...");
        match load_crs_shares_cache(&crs_cache_key) {
            Ok(cached_crs_shares) => {
                println!("✅ CRS分享缓存加载成功！");
                cached_crs_shares
            },
            Err(e) => {
                println!("⚠️ CRS缓存加载失败: {}，重新计算...", e);
                let crs_pack_start = Instant::now();
                let pk = pk.as_ref().expect("ProvingKey is required when CRS cache loading fails");
                let crs_shares = PackedProvingKeyShare::<Bn254>::pack_from_arkworks_proving_key(pk, pp);
                println!("✅ CRS分享重新计算完成: {:.2}s", crs_pack_start.elapsed().as_secs_f64());
                crs_shares
            }
        }
    } else {
        // 首次计算并保存缓存
        let crs_pack_start = Instant::now();
        println!("🔧 开始生成CRS分享...");
        let pk = pk.as_ref().expect("ProvingKey is required to generate CRS shares");
        let crs_shares = PackedProvingKeyShare::<Bn254>::pack_from_arkworks_proving_key(pk, pp);
        println!("✅ CRS分享生成完成: {:.2}s", crs_pack_start.elapsed().as_secs_f64());
        if task_id == 0 {
            save_crs_shares_cache(&crs_shares, &crs_cache_key).ok();
        }
        crs_shares
    };
    drop(pk);

    let crs_shares = Arc::new(crs_shares);
    let qap_shares = Arc::new(qap_shares);

    // 网络创建
    let network = Net::new_local_testnet(pp.n).await.unwrap();
    // 参与方并行工作（masks生成）
    let domain = qap_shares[0].domain;
    let root_of_unity = {
        let domain_size_double = 2 * domain.size();
        let domain_double = Radix2EvaluationDomain::<Bn254Fr>::new(domain_size_double).unwrap();
        domain_double.element(1)
    };
    println!("Domain size: {}", domain.size());

    // 生成masks
    let fft_masks = [
        FftMask::<Bn254Fr>::sample(
            true,
            root_of_unity,
            domain.group_gen_inv(),
            domain.size(),
            &pp,
            rng,
        ),
        FftMask::<Bn254Fr>::sample(
            true,
            root_of_unity,
            domain.group_gen_inv(),
            domain.size(),
            &pp,
            rng,
        ),
        FftMask::<Bn254Fr>::sample(
            true,
            root_of_unity,
            domain.group_gen_inv(),
            domain.size(),
            &pp,
            rng,
        ),
        FftMask::<Bn254Fr>::sample(
            false,
            Bn254Fr::one(),
            domain.group_gen(),
            domain.size(),
            &pp,
            rng,
        ),
        FftMask::<Bn254Fr>::sample(
            false,
            Bn254Fr::one(),
            domain.group_gen(),
            domain.size(),
            &pp,
            rng,
        ),
        FftMask::<Bn254Fr>::sample(
            false,
            Bn254Fr::one(),
            domain.group_gen(),
            domain.size(),
            &pp,
            rng,
        ),
    ];

    let f_degred_masks = DegRedMask::<Bn254Fr, Bn254Fr>::sample(
        &pp,
        Bn254Fr::from(1u32),
        domain.size() / pp.l,
        rng,
    );

    let g1_msm_mask: [Vec<MsmMask<G1>>; 4] = [
        MsmMask::sample(&pp, rng),
        MsmMask::sample(&pp, rng),
        MsmMask::sample(&pp, rng),
        MsmMask::sample(&pp, rng),
    ];

    let g2_msm_masks = MsmMask::<G2>::sample(&pp, rng);

    perf_collector.record_mpc_preprocessing(mpc_preprocessing_start.elapsed().as_millis() as f64);

    // 7. 客户端工作：witness秘密分享
    let client_sharing_start = Instant::now();
    let aux_assignment = &full_assignment[num_inputs..];
    let ax_shares = pack_from_witness::<Bn254>(&pp, aux_assignment.to_vec());
    let a_shares = pack_from_witness::<Bn254>(&pp, full_assignment[1..].to_vec());
    drop(full_assignment);
    perf_collector.record_witness_secret_sharing(client_sharing_start.elapsed().as_millis() as f64);

    // 8. MPC计算：分离纯计算时间和网络开销
    let mpc_total_start = Instant::now();
    let local_completion_barrier = Arc::new(Barrier::new(pp.n));
    let result: Vec<(G1, G2, G1, MpcDetailedMetrics)> = network
        .simulate_network_round(
            (crs_shares, pp, a_shares, ax_shares, qap_shares, r_shares, s_shares, fft_masks, f_degred_masks, g1_msm_mask, g2_msm_masks, local_completion_barrier,),
            |net, (crs_shares, pp, a_shares, ax_shares, qap_shares, r_shares, s_shares, fft_masks, f_degred_masks, g1_msm_mask, g2_msm_masks, local_completion_barrier,)| async move {
                let virtual_party_idx = net.party_id() as usize;
                let crs_share = crs_shares.get(virtual_party_idx).unwrap();
                let a_share = &a_shares[virtual_party_idx];
                let ax_share = &ax_shares[virtual_party_idx];
                let qap_share = qap_shares[virtual_party_idx].clone();
                let r_share = r_shares[virtual_party_idx];
                let s_share = s_shares[virtual_party_idx];
                let f_degred_mask = &f_degred_masks[virtual_party_idx];
                let g2_msm_mask = &g2_msm_masks[virtual_party_idx];
                let fft_mask = [
                    fft_masks[0][virtual_party_idx].clone(),
                    fft_masks[1][virtual_party_idx].clone(),
                    fft_masks[2][virtual_party_idx].clone(),
                    fft_masks[3][virtual_party_idx].clone(),
                    fft_masks[4][virtual_party_idx].clone(),
                    fft_masks[5][virtual_party_idx].clone(),
                ];

                let g1_msm_mask = [
                    g1_msm_mask[0][virtual_party_idx].clone(),
                    g1_msm_mask[1][virtual_party_idx].clone(),
                    g1_msm_mask[2][virtual_party_idx].clone(),
                    g1_msm_mask[3][virtual_party_idx].clone(),
                ];

                distributed_mpc_proof_generation(
                    &pp,
                    crs_share,
                    qap_share,
                    a_share,
                    ax_share,
                    r_share,
                    s_share,
                    &fft_mask,
                    f_degred_mask,
                    &g1_msm_mask,
                    g2_msm_mask,
                    local_completion_barrier,
                    &net,
                ).await
            },
        ).await;
    // 提取所有参与方的metrics并选择最慢的
    let all_party_metrics: Vec<MpcDetailedMetrics> = result.iter().map(|(_, _, _, metrics)| metrics.clone()).collect();
    perf_collector.record_slowest_mpc_metrics(&all_party_metrics);

    // 9. MPC阶段3：重构
    let mpc_reconstruction_start = Instant::now();
    let mut a_shares = Vec::new();
    let mut b_shares = Vec::new();
    let mut c_shares = Vec::new();
    for (a_share, b_share, c_share, _metrics) in result.into_iter() {
        a_shares.push(a_share);
        b_shares.push(b_share);
        c_shares.push(c_share);
    }

    let a = pp.unpack2(a_shares)[0];
    let b = pp.unpack2(b_shares)[0];
    let c = pp.unpack2(c_shares)[0];

    let mpc_proof = Proof::<Bn254> {
        a: a.into_affine(),
        b: b.into_affine(),
        c: c.into_affine(),
    };
    let mpc_reconstruction_time = mpc_reconstruction_start.elapsed().as_millis();
    perf_collector.record_mpc_reconstruction(mpc_reconstruction_time as f64);

    // 10. 验证证明
    let mpc_verify_start = Instant::now();
    let pvk = ark_groth16::verifier::prepare_verifying_key(&vk);
    let verified = Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
        &pvk,
        &public_inputs,
        &mpc_proof,
    ).unwrap();
    let mpc_verify_time = mpc_verify_start.elapsed().as_millis();
    assert!(verified, "MPC proof verification failed!");
    
    println!("🔍 Verification Breakdown:");
    println!("  └─ MPC proof: {} ms", mpc_verify_time);

    perf_collector.record_verification(mpc_verify_time as f64);

    // 计算proof size（使用序列化大小，不是文件大小）
    let mut proof_bytes = Vec::new();
    let proof_size = match mpc_proof.serialize_with_mode(&mut proof_bytes, Compress::Yes) {
        Ok(_) => {
            println!("📊 Task {} proof size: {} bytes", task_id, proof_bytes.len());
            proof_bytes.len()
        },
        Err(e) => {
            eprintln!("❌ Task {} failed to serialize proof for size calculation: {}", task_id, e);
            0
        }
    };
    // 11. 序列化证明
    let serialization_start = Instant::now();
    let serializable_proof = SerializableProof::from_groth16_proof(&mpc_proof, &public_inputs);
    
    // 创建proof_data目录
    fs::create_dir_all("proof_data").expect("Failed to create proof_data directory");
    
    if party_id == 0 {  // party_id是MPC参与方ID，只有参与方0保存
        use ark_serialize::CanonicalSerialize;
        
        // 保存证明文件，使用任务ID(task_id)作为文件名
        let proof_filename = format!("proof_data/regex_proof_{}.json", task_id);  // task_id是任务ID
        let proof_json = serde_json::to_string_pretty(&serializable_proof).unwrap();

        // 保存proof到文件（可选，用于验证等）
        match fs::write(&proof_filename, proof_json) {
            Ok(_) => {
                println!("✅ Task {} proof saved to: {}", task_id, proof_filename);
            },
            Err(e) => {
                eprintln!("❌ Task {} failed to save proof: {}", task_id, e);
            }
        }

        // 只有第一个任务(task_id==0)保存验证密钥
        if task_id == 0 {  // task_id是任务ID
            let mut vk_bytes = Vec::new();
            vk.serialize_compressed(&mut vk_bytes).expect("Failed to serialize verification key");
            if let Err(e) = fs::write("proof_data/verification_key.bin", vk_bytes) {
                eprintln!("❌ Failed to save verification key: {}", e);
            } else {
                println!("✅ Verification key saved to: proof_data/verification_key.bin");
            }
        }
        // commitment大小（Poseidon hash输出大小）
        let commitment_size = 32u64;
        
        // 保存性能指标
        perf_collector.save_metrics(&circuit_info, proof_size, commitment_size);
    } else {
        // 其他参与方不保存文件，但仍需记录0大小用于性能指标
        //let proof_size = 128u64;
        let commitment_size = 32u64;
        perf_collector.save_metrics(&circuit_info, proof_size, commitment_size);
    }
    
    perf_collector.record_serialization(serialization_start.elapsed().as_millis() as f64);

    // 最后的性能输出（删除arkworks比较和不存在的字段）
    println!("✅ Task {} completed successfully", party_id);
    println!("📊 Performance Summary:");
    println!("  ├─ Witness generation: {:.2} ms", perf_collector.witness_generation_time_ms);
    println!("  ├─ Circuit building: {:.2} ms", perf_collector.circuit_building_time_ms);
    println!("  ├─ MPC preprocessing: {:.2} ms", perf_collector.mpc_preprocessing_time_ms);
    println!("  ├─ witness_secret_sharing: {:.2} ms", perf_collector.witness_secret_sharing_time_ms);
    println!("  ├─ MPC R1CS to QAP: {:.2} ms", perf_collector.mpc_r1cs_to_qap_ms);
    println!("  ├─ MPC computation (slowest party): {:.2} ms", perf_collector.mpc_total_time_ms);
    println!("  │   ├─ H computation: {:.2} ms", perf_collector.mpc_h_computation_ms);
    println!("  │   ├─ A computation: {:.2} ms", perf_collector.mpc_a_computation_ms);
    println!("  │   ├─ B(G1) computation: {:.2} ms", perf_collector.mpc_b_g1_computation_ms);
    println!("  │   ├─ B(G2) computation: {:.2} ms", perf_collector.mpc_b_g2_computation_ms);
    println!("  │   └─ C computation: {:.2} ms", perf_collector.mpc_c_computation_ms);
    println!("  ├─ MPC reconstruction: {:.2} ms", perf_collector.mpc_reconstruction_time_ms);
    println!("  └─ Client total: {:.2} ms", perf_collector.calculate_client_total_time());
}
