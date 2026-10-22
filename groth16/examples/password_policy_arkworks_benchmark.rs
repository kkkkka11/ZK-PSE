use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use csv::Writer;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

const MSG_BYTES: usize = 20;
const SALT_BYTES: usize = 20;
const POSEIDON_COMMITMENT_BYTES: usize = 32;

#[derive(Debug, Clone)]
struct Args {
    variant: String,
    optimized_dir: String,
    noshare_dir: String,
    good_dir: String,
    bad_dir: String,
    repeats: usize,
    setup_repeats: usize,
    regex_count: usize,
    regex_id: Option<usize>,
    max_tasks: usize,
    case_filter: String,
    reverse_circuit_order: bool,
    out_dir: String,
}

#[derive(Debug, Deserialize)]
struct Witness {
    password: String,
    k: String,
}

#[derive(Debug, Clone, Serialize)]
struct SetupRawRow {
    circuit_set: String,
    regex_id: usize,
    repeat_id: usize,
    constraints: usize,
    variables: usize,
    public_inputs: usize,
    setup_time_ms: f64,
    status: String,
    error: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProofRawRow {
    circuit_set: String,
    regex_id: usize,
    case_type: String,
    witness_file: String,
    witness_index: usize,
    repeat_id: usize,
    expected_match: u8,
    constraints: usize,
    prove_time_ms: f64,
    verify_time_ms: f64,
    proof_size_bytes: usize,
    commitment_size_bytes: usize,
    status: String,
    error: String,
}

#[derive(Debug, Clone, Serialize)]
struct SummaryRow {
    circuit_set: String,
    regex_id: usize,
    case_type: String,
    constraints: usize,
    setup_time_ms_avg: f64,
    prove_time_ms_avg: f64,
    verify_time_ms_avg: f64,
    proof_size_bytes_avg: f64,
    commitment_size_bytes_avg: f64,
    setup_success_count: usize,
    setup_fail_count: usize,
    proof_success_count: usize,
    proof_fail_count: usize,
}

#[derive(Debug, Clone)]
struct CircuitInfo {
    constraints: usize,
    variables: usize,
    public_inputs: usize,
}

struct PreparedCircuit {
    circuit_set: String,
    regex_id: usize,
    cfg: CircomConfig<Bn254>,
    pk: ark_groth16::ProvingKey<Bn254>,
    vk: ark_groth16::VerifyingKey<Bn254>,
    info: CircuitInfo,
}

fn usage(program: &str) {
    eprintln!(
        "Usage: {program} [options]\n\
         \n\
         Options:\n\
           --variant <name>       all (default), G16-Optimized, or G16-Base\n\
           --optimized <dir>      Default: fixtures/password_policies_5_ascii\n\
           --noshare <dir>        Default: fixtures/password_policies_5_ascii_noshare\n\
           --good <dir>           Default: fixtures/regex/witness-good\n\
           --bad <dir>            Default: fixtures/regex/witness-bad\n\
           --repeats <n>          Prove/verify repeats per witness. Default: 10\n\
           --setup-repeats <n>    Setup repeats per circuit. Default: 10\n\
           --regex-count <n>      Default: 5\n\
           --regex-id <n>         Run only one regex (for example, 1 or 3)\n\
           --max-tasks <n>        Witnesses per good/bad case. Default: all\n\
           --case <name>          all (default), good, or bad\n\
           --reverse-circuit-order Run G16-Base before G16-Optimized for order-control tests\n\
           --out <dir>            Default: benchmark_results/g16_baselines\n"
    );
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let raw: Vec<String> = std::env::args().collect();
    let mut args = Args {
        variant: "all".to_string(),
        optimized_dir: "fixtures/password_policies_5_ascii".to_string(),
        noshare_dir: "fixtures/password_policies_5_ascii_noshare".to_string(),
        good_dir: "fixtures/regex/witness-good".to_string(),
        bad_dir: "fixtures/regex/witness-bad".to_string(),
        repeats: 10,
        setup_repeats: 10,
        regex_count: 5,
        regex_id: None,
        max_tasks: usize::MAX,
        case_filter: "all".to_string(),
        reverse_circuit_order: false,
        out_dir: "benchmark_results/g16_baselines".to_string(),
    };

    let mut i = 1;
    while i < raw.len() {
        let value = |i: usize| -> Result<String, Box<dyn std::error::Error>> {
            raw.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("Missing value for {}", raw[i]).into())
        };
        match raw[i].as_str() {
            "--help" | "-h" => {
                usage(&raw[0]);
                std::process::exit(0);
            }
            "--variant" => {
                args.variant = value(i)?;
                i += 2;
            }
            "--optimized" => {
                args.optimized_dir = value(i)?;
                i += 2;
            }
            "--noshare" => {
                args.noshare_dir = value(i)?;
                i += 2;
            }
            "--good" => {
                args.good_dir = value(i)?;
                i += 2;
            }
            "--bad" => {
                args.bad_dir = value(i)?;
                i += 2;
            }
            "--repeats" => {
                args.repeats = value(i)?.parse()?;
                i += 2;
            }
            "--setup-repeats" => {
                args.setup_repeats = value(i)?.parse()?;
                i += 2;
            }
            "--regex-count" => {
                args.regex_count = value(i)?.parse()?;
                i += 2;
            }
            "--regex-id" => {
                args.regex_id = Some(value(i)?.parse()?);
                i += 2;
            }
            "--max-tasks" => {
                args.max_tasks = value(i)?.parse()?;
                i += 2;
            }
            "--case" => {
                args.case_filter = value(i)?;
                i += 2;
            }
            "--reverse-circuit-order" => {
                args.reverse_circuit_order = true;
                i += 1;
            }
            "--out" => {
                args.out_dir = value(i)?;
                i += 2;
            }
            other => return Err(format!("Unknown argument: {other}").into()),
        }
    }

    if !matches!(args.variant.as_str(), "all" | "G16-Optimized" | "G16-Base") {
        return Err("--variant must be all, G16-Optimized, or G16-Base".into());
    }
    if !matches!(args.case_filter.as_str(), "all" | "good" | "bad") {
        return Err("--case must be all, good, or bad".into());
    }

    Ok(args)
}

fn circuit_paths(base_dir: &str, regex_id: usize) -> (String, String) {
    let r1cs = format!(
        "{}/regex_{}/build/GeneratedRegex{}.r1cs",
        base_dir, regex_id, regex_id
    );
    let wasm = format!(
        "{}/regex_{}/build/GeneratedRegex{}_js/GeneratedRegex{}.wasm",
        base_dir, regex_id, regex_id, regex_id
    );
    (r1cs, wasm)
}

fn witness_sort_key(path: &Path) -> usize {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(|s| {
            s.chars()
                .filter(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse::<usize>()
                .unwrap_or(usize::MAX)
        })
        .unwrap_or(usize::MAX)
}

fn collect_witness_files(dir: &str) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            files.push(path);
        }
    }
    files.sort_by_key(|p| witness_sort_key(p));
    if files.is_empty() {
        return Err(format!("No witness JSON files found in {dir}").into());
    }
    Ok(files)
}

fn read_witness(path: &Path) -> Result<Witness, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn password_to_bytes(password: &str) -> Result<Vec<u8>, std::io::Error> {
    if password.as_bytes().len() > MSG_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("password exceeds {MSG_BYTES}-byte circuit limit"),
        ));
    }
    let mut msg = vec![0u8; MSG_BYTES];
    for (i, byte) in password.as_bytes().iter().enumerate() {
        msg[i] = *byte;
    }
    Ok(msg)
}

fn salt_to_bytes(k: &str) -> Result<Vec<u8>, std::io::Error> {
    let hex = k.trim();
    if hex.len() != SALT_BYTES * 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("salt must be exactly {SALT_BYTES}-byte hexadecimal"),
        ));
    }

    (0..SALT_BYTES)
        .map(|index| {
            u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "salt contains invalid hexadecimal",
                )
            })
        })
        .collect()
}

fn push_inputs(
    builder: &mut CircomBuilder<Bn254>,
    witness: &Witness,
    expected_match: u8,
) -> Result<(), std::io::Error> {
    for byte in password_to_bytes(&witness.password)? {
        builder.push_input("msg", byte as i32);
    }
    for byte in salt_to_bytes(&witness.k)? {
        builder.push_input("salt", byte as i32);
    }
    builder.push_input("expected_match", expected_match as i32);
    Ok(())
}

fn inspect_circuit(
    cfg: &CircomConfig<Bn254>,
    sample_witness: &Witness,
    expected_match: u8,
) -> Result<CircuitInfo, Box<dyn std::error::Error>> {
    let mut builder = CircomBuilder::new(cfg.clone());
    push_inputs(&mut builder, sample_witness, expected_match)?;
    let circom = builder.build()?;
    let public_inputs = circom
        .get_public_inputs()
        .ok_or("Failed to get public inputs")?;
    let constraints = cfg.r1cs.constraints.len();
    let variables = cfg.r1cs.num_variables;

    Ok(CircuitInfo {
        constraints,
        variables,
        public_inputs: public_inputs.len(),
    })
}

fn avg(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

// Benchmark-only deterministic randomness. The domains match the fixed seeds
// used by the local ZK-PSE experiment path; deployment must use a CSPRNG.
fn benchmark_rng(domain: u8, regex_id: usize, witness_index: usize, repeat_id: usize) -> StdRng {
    let mut seed = [domain; 32];
    seed[8..16].copy_from_slice(&(regex_id as u64).to_le_bytes());
    seed[16..24].copy_from_slice(&(witness_index as u64).to_le_bytes());
    seed[24..32].copy_from_slice(&(repeat_id as u64).to_le_bytes());
    StdRng::from_seed(seed)
}

fn run_setup_repeats(
    circuit_set: &str,
    regex_id: usize,
    cfg: &CircomConfig<Bn254>,
    info: &CircuitInfo,
    repeats: usize,
    setup_rows: &mut Vec<SetupRawRow>,
) -> Result<
    (
        ark_groth16::ProvingKey<Bn254>,
        ark_groth16::VerifyingKey<Bn254>,
    ),
    Box<dyn std::error::Error>,
> {
    let mut selected = None;
    for repeat_id in 1..=repeats {
        let setup_circuit = CircomBuilder::new(cfg.clone()).setup();
        let mut rng = benchmark_rng(42, regex_id, 0, repeat_id);
        let start = Instant::now();
        match Groth16::<Bn254, CircomReduction>::circuit_specific_setup(setup_circuit, &mut rng) {
            Ok((pk, vk)) => {
                let setup_time_ms = start.elapsed().as_secs_f64() * 1000.0;
                setup_rows.push(SetupRawRow {
                    circuit_set: circuit_set.to_string(),
                    regex_id,
                    repeat_id,
                    constraints: info.constraints,
                    variables: info.variables,
                    public_inputs: info.public_inputs,
                    setup_time_ms,
                    status: "ok".to_string(),
                    error: String::new(),
                });
                selected = Some((pk, vk));
            }
            Err(error) => {
                setup_rows.push(SetupRawRow {
                    circuit_set: circuit_set.to_string(),
                    regex_id,
                    repeat_id,
                    constraints: info.constraints,
                    variables: info.variables,
                    public_inputs: info.public_inputs,
                    setup_time_ms: start.elapsed().as_secs_f64() * 1000.0,
                    status: "error".to_string(),
                    error: error.to_string(),
                });
            }
        }
    }

    selected.ok_or_else(|| "All setup attempts failed".into())
}

fn run_proof_once(
    cfg: &CircomConfig<Bn254>,
    pk: &ark_groth16::ProvingKey<Bn254>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
    witness: &Witness,
    expected_match: u8,
    rng: &mut StdRng,
) -> Result<(f64, f64, usize), Box<dyn std::error::Error>> {
    let mut builder = CircomBuilder::new(cfg.clone());
    push_inputs(&mut builder, witness, expected_match)?;
    let circom = builder.build()?;
    let public_inputs = circom
        .get_public_inputs()
        .ok_or("Failed to get public inputs")?;

    let prove_start = Instant::now();
    let proof = Groth16::<Bn254, CircomReduction>::prove(pk, circom, rng)?;
    let prove_time_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    let pvk = ark_groth16::verifier::prepare_verifying_key(vk);
    let verify_start = Instant::now();
    let verified = Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
        &pvk,
        &public_inputs,
        &proof,
    )?;
    let verify_time_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    if !verified {
        return Err("Proof verification returned false".into());
    }

    let mut proof_bytes = Vec::new();
    proof.serialize_with_mode(&mut proof_bytes, Compress::Yes)?;
    Ok((prove_time_ms, verify_time_ms, proof_bytes.len()))
}

fn record_proof(
    prepared: &PreparedCircuit,
    case_type: &str,
    expected_match: u8,
    witness_path: &Path,
    witness_index: usize,
    repeat_id: usize,
    proof_rows: &mut Vec<ProofRawRow>,
) {
    let witness_file = witness_path.to_string_lossy().to_string();
    let result = read_witness(witness_path).and_then(|witness| {
        let mut rng = benchmark_rng(44, prepared.regex_id, witness_index, repeat_id);
        run_proof_once(
            &prepared.cfg,
            &prepared.pk,
            &prepared.vk,
            &witness,
            expected_match,
            &mut rng,
        )
    });

    match result {
        Ok((prove_time_ms, verify_time_ms, proof_size_bytes)) => {
            proof_rows.push(ProofRawRow {
                circuit_set: prepared.circuit_set.clone(),
                regex_id: prepared.regex_id,
                case_type: case_type.to_string(),
                witness_file,
                witness_index,
                repeat_id,
                expected_match,
                constraints: prepared.info.constraints,
                prove_time_ms,
                verify_time_ms,
                proof_size_bytes,
                commitment_size_bytes: POSEIDON_COMMITMENT_BYTES,
                status: "ok".to_string(),
                error: String::new(),
            });
        }
        Err(error) => {
            proof_rows.push(ProofRawRow {
                circuit_set: prepared.circuit_set.clone(),
                regex_id: prepared.regex_id,
                case_type: case_type.to_string(),
                witness_file,
                witness_index,
                repeat_id,
                expected_match,
                constraints: prepared.info.constraints,
                prove_time_ms: 0.0,
                verify_time_ms: 0.0,
                proof_size_bytes: 0,
                commitment_size_bytes: POSEIDON_COMMITMENT_BYTES,
                status: "error".to_string(),
                error: error.to_string(),
            });
        }
    }
}

fn run_interleaved_cases(
    prepared_circuits: &[PreparedCircuit],
    good_witnesses: &[PathBuf],
    bad_witnesses: &[PathBuf],
    case_filter: &str,
    repeats: usize,
    proof_rows: &mut Vec<ProofRawRow>,
) {
    let witness_count = good_witnesses.len().max(bad_witnesses.len());
    let case_order: &[bool] = match case_filter {
        "good" => &[true],
        "bad" => &[false],
        _ => &[true, false],
    };
    let jobs_per_round = prepared_circuits.len() * case_order.len();
    let selected_witnesses = case_order
        .iter()
        .map(|is_good| {
            if *is_good {
                good_witnesses.len()
            } else {
                bad_witnesses.len()
            }
        })
        .sum::<usize>();
    let total_jobs = prepared_circuits.len() * selected_witnesses * repeats;
    let progress_interval = (total_jobs / 20).max(1);
    let progress_start = Instant::now();
    let mut completed_jobs = 0usize;

    println!("  proof jobs: {total_jobs}");
    let _ = io::stdout().flush();

    for witness_index in 0..witness_count {
        for repeat_id in 1..=repeats {
            // Rotate the start position so each circuit/case pair is sampled
            // equally across early and late positions in the local run.
            let shift = (witness_index * repeats + repeat_id - 1) % jobs_per_round;
            for offset in 0..jobs_per_round {
                let job_index = (offset + shift) % jobs_per_round;
                let prepared = &prepared_circuits[job_index / case_order.len()];
                let is_good = case_order[job_index % case_order.len()];
                let (case_type, expected_match, witnesses) = if is_good {
                    ("good", 1, good_witnesses)
                } else {
                    ("bad", 0, bad_witnesses)
                };

                if let Some(witness_path) = witnesses.get(witness_index) {
                    record_proof(
                        prepared,
                        case_type,
                        expected_match,
                        witness_path,
                        witness_index,
                        repeat_id,
                        proof_rows,
                    );
                    completed_jobs += 1;
                    if completed_jobs % progress_interval == 0 || completed_jobs == total_jobs {
                        let elapsed = progress_start.elapsed().as_secs_f64();
                        let eta = if completed_jobs == 0 {
                            0.0
                        } else {
                            elapsed * (total_jobs - completed_jobs) as f64
                                / completed_jobs as f64
                        };
                        println!(
                            "  progress: {completed_jobs}/{total_jobs} ({:.1}%), elapsed {:.1}s, ETA {:.1}s",
                            100.0 * completed_jobs as f64 / total_jobs as f64,
                            elapsed,
                            eta
                        );
                        let _ = io::stdout().flush();
                    }
                }
            }
        }
    }
}

fn write_csv<T: Serialize>(path: &Path, rows: &[T]) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = Writer::from_path(path)?;
    for row in rows {
        writer.serialize(row)?;
    }
    writer.flush()?;
    Ok(())
}

fn summarize(
    circuit_sets: &[(&str, String)],
    regex_ids: &[usize],
    case_types: &[&str],
    setup_rows: &[SetupRawRow],
    proof_rows: &[ProofRawRow],
) -> Vec<SummaryRow> {
    let mut rows = Vec::new();
    for (circuit_set, _) in circuit_sets {
        for &regex_id in regex_ids {
            let setup_for_circuit: Vec<&SetupRawRow> = setup_rows
                .iter()
                .filter(|r| r.circuit_set == *circuit_set && r.regex_id == regex_id)
                .collect();
            let setup_ok: Vec<f64> = setup_for_circuit
                .iter()
                .filter(|r| r.status == "ok")
                .map(|r| r.setup_time_ms)
                .collect();
            let setup_success_count = setup_ok.len();
            let setup_fail_count = setup_for_circuit.len().saturating_sub(setup_success_count);
            let setup_avg = avg(&setup_ok);

            for case_type in case_types {
                let proofs: Vec<&ProofRawRow> = proof_rows
                    .iter()
                    .filter(|r| {
                        r.circuit_set == *circuit_set
                            && r.regex_id == regex_id
                            && r.case_type == *case_type
                    })
                    .collect();
                let ok: Vec<&ProofRawRow> =
                    proofs.iter().copied().filter(|r| r.status == "ok").collect();
                let proof_success_count = ok.len();
                let proof_fail_count = proofs.len().saturating_sub(proof_success_count);
                let constraints = proofs
                    .first()
                    .map(|r| r.constraints)
                    .or_else(|| setup_for_circuit.first().map(|r| r.constraints))
                    .unwrap_or(0);

                rows.push(SummaryRow {
                    circuit_set: circuit_set.to_string(),
                    regex_id,
                    case_type: case_type.to_string(),
                    constraints,
                    setup_time_ms_avg: setup_avg,
                    prove_time_ms_avg: avg(
                        &ok.iter().map(|r| r.prove_time_ms).collect::<Vec<_>>(),
                    ),
                    verify_time_ms_avg: avg(
                        &ok.iter().map(|r| r.verify_time_ms).collect::<Vec<_>>(),
                    ),
                    proof_size_bytes_avg: avg(
                        &ok.iter()
                            .map(|r| r.proof_size_bytes as f64)
                            .collect::<Vec<_>>(),
                    ),
                    commitment_size_bytes_avg: avg(
                        &ok.iter()
                            .map(|r| r.commitment_size_bytes as f64)
                            .collect::<Vec<_>>(),
                    ),
                    setup_success_count,
                    setup_fail_count,
                    proof_success_count,
                    proof_fail_count,
                });
            }
        }
    }
    rows
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    fs::create_dir_all(&args.out_dir)?;

    let mut good_witnesses = collect_witness_files(&args.good_dir)?;
    let mut bad_witnesses = collect_witness_files(&args.bad_dir)?;
    good_witnesses.truncate(args.max_tasks);
    bad_witnesses.truncate(args.max_tasks);
    if good_witnesses.is_empty() || bad_witnesses.is_empty() {
        return Err("--max-tasks must be positive".into());
    }
    let sample_good = read_witness(&good_witnesses[0])?;
    let mut circuit_sets = match args.variant.as_str() {
        "G16-Optimized" => vec![("G16-Optimized", args.optimized_dir.clone())],
        "G16-Base" => vec![("G16-Base", args.noshare_dir.clone())],
        _ => vec![
            ("G16-Optimized", args.optimized_dir.clone()),
            ("G16-Base", args.noshare_dir.clone()),
        ],
    };
    if args.reverse_circuit_order {
        circuit_sets.reverse();
    }

    println!("Arkworks Groth16 password-policy benchmark");
    println!("  variant:       {}", args.variant);
    println!("  case:          {}", args.case_filter);
    println!("  repeats:       {}", args.repeats);
    println!("  setup repeats: {}", args.setup_repeats);
    println!("  good witnesses: {}", good_witnesses.len());
    println!("  bad witnesses:  {}", bad_witnesses.len());
    println!("  output: {}", args.out_dir);

    let mut setup_rows = Vec::new();
    let mut proof_rows = Vec::new();
    let regex_ids: Vec<usize> = match args.regex_id {
        Some(regex_id) => vec![regex_id],
        None => (1..=args.regex_count).collect(),
    };
    let case_types: Vec<&str> = match args.case_filter.as_str() {
        "good" => vec!["good"],
        "bad" => vec!["bad"],
        _ => vec!["good", "bad"],
    };

    for &regex_id in &regex_ids {
        let mut prepared_circuits = Vec::new();
        for (circuit_set, base_dir) in &circuit_sets {
            let (r1cs_path, wasm_path) = circuit_paths(base_dir, regex_id);
            if !Path::new(&r1cs_path).exists() {
                return Err(format!("R1CS file not found: {r1cs_path}").into());
            }
            if !Path::new(&wasm_path).exists() {
                return Err(format!("WASM file not found: {wasm_path}").into());
            }

            println!("\n[{circuit_set} regex_{regex_id}]");
            println!("  r1cs: {r1cs_path}");
            println!("  wasm: {wasm_path}");

            let cfg = CircomConfig::<Bn254>::new(&wasm_path, &r1cs_path)?;
            let info = inspect_circuit(&cfg, &sample_good, 1)?;
            println!(
                "  constraints: {}, variables: {}, public inputs/signals: {}",
                info.constraints, info.variables, info.public_inputs
            );

            let (pk, vk) = run_setup_repeats(
                circuit_set,
                regex_id,
                &cfg,
                &info,
                args.setup_repeats,
                &mut setup_rows,
            )?;

            prepared_circuits.push(PreparedCircuit {
                circuit_set: circuit_set.to_string(),
                regex_id,
                cfg,
                pk,
                vk,
                info,
            });
        }

        run_interleaved_cases(
            &prepared_circuits,
            &good_witnesses,
            &bad_witnesses,
            &args.case_filter,
            args.repeats,
            &mut proof_rows,
        );
    }

    let summary_rows = summarize(
        &circuit_sets,
        &regex_ids,
        &case_types,
        &setup_rows,
        &proof_rows,
    );
    let out_dir = Path::new(&args.out_dir);
    write_csv(&out_dir.join("setup_raw.csv"), &setup_rows)?;
    write_csv(&out_dir.join("proof_raw.csv"), &proof_rows)?;
    write_csv(&out_dir.join("summary.csv"), &summary_rows)?;

    println!("\nDone.");
    println!("  {}", out_dir.join("setup_raw.csv").display());
    println!("  {}", out_dir.join("proof_raw.csv").display());
    println!("  {}", out_dir.join("summary.csv").display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Benchmark failed: {error}");
        std::process::exit(1);
    }
}
