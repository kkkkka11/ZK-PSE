#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

function usage() {
    console.log(`Usage:
  node build_multi_dfa_experiment.js <generated_regex_dir> [output_dir] [--compile] [--verbose]

Example:
  node build_lookahead_circuits.js password_policies.txt /tmp/lookahead --compile
  node build_multi_dfa_experiment.js /tmp/lookahead/regex_1 /tmp/multi-dfa-regex1 --compile

This is an experimental multi-DFA pass. It keeps each DFA's transition logic,
but shares msg -> in normalization and byte range checks across all conditions.`);
}

function run(command, options = {}) {
    if (options.verbose) {
        console.log(`$ ${command}`);
    }
    return execSync(command, {
        cwd: options.cwd || process.cwd(),
        encoding: "utf8",
        stdio: options.verbose ? "inherit" : "pipe",
    });
}

function readJson(filePath) {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function braceDelta(content) {
    let delta = 0;
    let escaped = false;
    let inString = null;

    for (const ch of content) {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch === "\\") {
            escaped = true;
            continue;
        }
        if (inString) {
            if (ch === inString) {
                inString = null;
            }
            continue;
        }
        if (ch === "\"" || ch === "'") {
            inString = ch;
            continue;
        }
        if (ch === "{") delta += 1;
        if (ch === "}") delta -= 1;
    }

    return delta;
}

function findMatchingBrace(content, openIndex) {
    let depth = 0;
    let escaped = false;
    let inString = null;

    for (let i = openIndex; i < content.length; i++) {
        const ch = content[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch === "\\") {
            escaped = true;
            continue;
        }
        if (inString) {
            if (ch === inString) {
                inString = null;
            }
            continue;
        }
        if (ch === "\"" || ch === "'") {
            inString = ch;
            continue;
        }
        if (ch === "{") depth += 1;
        if (ch === "}") depth -= 1;
        if (depth === 0) {
            return i;
        }
    }

    throw new Error(`No matching brace found at index ${openIndex}`);
}

function extractTemplate(content, templateName) {
    const marker = `template ${templateName}(`;
    const start = content.indexOf(marker);
    if (start === -1) {
        throw new Error(`Template not found: ${templateName}`);
    }

    const openBrace = content.indexOf("{", start);
    if (openBrace === -1) {
        throw new Error(`Template has no body: ${templateName}`);
    }

    const closeBrace = findMatchingBrace(content, openBrace);
    return content.slice(start, closeBrace + 1);
}

function transformTemplate(templateContent, oldName, newName) {
    let out = templateContent.replace(
        new RegExp(`template\\s+${oldName}\\s*\\(`),
        `template ${newName}(`
    );

    out = out.replace(
        /\n\s*signal input msg\[msg_bytes\];\n\s*signal output out;\n\s*\n\s*var num_bytes = msg_bytes\+1;\n\s*signal in\[num_bytes\];\n\s*signal in_range_checks\[msg_bytes\];\n\s*in\[0\]\s*<==\s*255;\n\s*for \(var i = 0; i < msg_bytes; i\+\+\) \{\n\s*in_range_checks\[i\]\s*<==\s*LessThan\(8\)\(\[msg\[i\], 255\]\);\n\s*in_range_checks\[i\]\s*===\s*1;\n\s*in\[i\+1\]\s*<==\s*msg\[i\];\n\s*\}\n/,
        "\n\tsignal input in[msg_bytes+1];\n\tsignal output out;\n\n\tvar num_bytes = msg_bytes+1;\n"
    );

    if (out.includes("signal input msg[msg_bytes]") || out.includes("in_range_checks")) {
        throw new Error(`Failed to remove duplicated input preparation from ${oldName}`);
    }

    if (braceDelta(out) !== 0) {
        throw new Error(`Transformed template has unbalanced braces: ${oldName}`);
    }

    return out;
}

function passwordHashTemplate() {
    return `template PasswordHash20() {
    signal input msg[20];
    signal input k;
    signal output hash;

    component left_hasher = Poseidon(10);
    component right_hasher = Poseidon(10);
    component final_hasher = Poseidon(3);

    for (var i = 0; i < 10; i++) {
        left_hasher.inputs[i] <== msg[i];
        right_hasher.inputs[i] <== msg[i + 10];
    }

    final_hasher.inputs[0] <== k;
    final_hasher.inputs[1] <== left_hasher.out;
    final_hasher.inputs[2] <== right_hasher.out;

    hash <== final_hasher.out;
}`;
}

function combinedOutputSnippet(conditions) {
    const lines = [];
    lines.push(`    signal condition_out[${conditions.length}];`);

    for (let i = 0; i < conditions.length; i++) {
        const templateName = `${conditions[i].templateName}SharedIn`;
        lines.push(`    component checker_${i} = ${templateName}(maxLength);`);
        for (let j = 0; j <= 20; j++) {
            lines.push(`    checker_${i}.in[${j}] <== shared_in[${j}];`);
        }
        lines.push(`    condition_out[${i}] <== ${conditions[i].negate ? "1 - " : ""}checker_${i}.out;`);
        lines.push("");
    }

    if (conditions.length === 1) {
        lines.push("    regex_match <== condition_out[0];");
        return lines.join("\n");
    }

    lines.push(`    signal and_acc[${conditions.length - 1}];`);
    lines.push("    and_acc[0] <== condition_out[0] * condition_out[1];");
    for (let i = 2; i < conditions.length; i++) {
        lines.push(`    and_acc[${i - 1}] <== and_acc[${i - 2}] * condition_out[${i}];`);
    }
    lines.push(`    regex_match <== and_acc[${conditions.length - 2}];`);
    return lines.join("\n");
}

function build(generatedRegexDir, outputDir, options) {
    const metadataPath = path.join(generatedRegexDir, "metadata.json");
    if (!fs.existsSync(metadataPath)) {
        throw new Error(`metadata.json not found in ${generatedRegexDir}`);
    }

    const metadata = readJson(metadataPath);
    if (metadata.msg_bytes !== 20) {
        throw new Error(`Only msg_bytes=20 is supported by this experiment, got ${metadata.msg_bytes}`);
    }

    fs.mkdirSync(outputDir, { recursive: true });

    const transformedTemplates = metadata.conditions.map((condition) => {
        const circomPath = path.join(generatedRegexDir, condition.includePath.replace(/^\.\//, ""));
        const content = fs.readFileSync(circomPath, "utf8");
        const template = extractTemplate(content, condition.templateName);
        return transformTemplate(template, condition.templateName, `${condition.templateName}SharedIn`);
    });

    const wrapperName = `MultiDfaRegex${metadata.id}`;
    const outPath = path.join(outputDir, `${wrapperName}.circom`);
    const sourceComments = metadata.conditions
        .map(
            (condition, index) =>
                `// condition ${index}: ${condition.negate ? "NOT " : ""}${condition.regex}  (from ${condition.source})`
        )
        .join("\n");

    const content = `pragma circom 2.1.5;

include "@zk-email/zk-regex-circom/circuits/regex_helpers.circom";
include "circomlib/circuits/poseidon.circom";

${sourceComments}

${transformedTemplates.join("\n\n")}

${passwordHashTemplate()}

template ${wrapperName}(maxLength) {
    signal input msg[maxLength];
    signal input k;
    signal output hash;
    signal output regex_match;

    var num_bytes = maxLength + 1;
    signal shared_in[num_bytes];
    signal in_range_checks[maxLength];

    shared_in[0] <== 255;
    for (var i = 0; i < maxLength; i++) {
        in_range_checks[i] <== LessThan(8)([msg[i], 255]);
        in_range_checks[i] === 1;
        shared_in[i + 1] <== msg[i];
    }

${combinedOutputSnippet(metadata.conditions)}

    component password_hash = PasswordHash20();
    for (var i = 0; i < maxLength; i++) {
        password_hash.msg[i] <== msg[i];
    }
    password_hash.k <== k;
    hash <== password_hash.hash;

    regex_match === 1;
}

component main = ${wrapperName}(20);
`;

    fs.writeFileSync(outPath, content);
    fs.writeFileSync(
        path.join(outputDir, "metadata.json"),
        JSON.stringify(
            {
                source: generatedRegexDir,
                wrapper: path.basename(outPath),
                note: "Experimental multi-DFA shared-input circuit. DFA transitions are preserved; input normalization and byte range checks are shared.",
                conditions: metadata.conditions,
            },
            null,
            2
        )
    );

    if (options.compile) {
        const buildDir = path.join(outputDir, "build");
        fs.mkdirSync(buildDir, { recursive: true });
        run(
            `circom -l node_modules ${JSON.stringify(outPath)} --r1cs --wasm --sym --O0 -o ${JSON.stringify(buildDir)}`,
            options
        );
    }

    console.log(`Generated experimental multi-DFA circuit: ${outPath}`);
}

function main() {
    const args = process.argv.slice(2);
    if (args.length === 0 || args.includes("--help")) {
        usage();
        return;
    }

    const inputDir = path.resolve(args[0]);
    const outputDir = path.resolve(args[1] || "./multi-dfa-experiment");
    const options = {
        compile: args.includes("--compile"),
        verbose: args.includes("--verbose"),
        cwd: process.cwd(),
    };

    try {
        build(inputDir, outputDir, options);
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}
