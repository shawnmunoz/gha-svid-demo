// Runs inside a GitHub Actions job. Attests to Defakto using the job's GitHub
// OIDC token (no secrets, no agent) and prints the X.509 and JWT SVIDs issued.
//
// Configured entirely through environment (set by the workflow):
//   DEFAKTO_ATTESTORS=github
//   DEFAKTO_TRUST_DOMAIN_ID=td-...
//   SVID_AUDIENCE=<audience for the JWT-SVID>
import { appendFileSync } from "node:fs";
import * as core from "@actions/core";
import { WorkloadAPIClient, SpiffeError, parseAndValidateJwtSVID } from "@defakto/spiffe";

const audience = process.env.SVID_AUDIENCE ?? "github-actions-demo";
const summary = [];

function section(title) {
    console.log(`\n==================== ${title} ====================`);
}

function decodeJwtPayload(token) {
    return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
}

try {
    // 1. What GitHub vouches for. The GithubAttestor fetches this same token
    //    itself; we decode a copy only to show what Defakto receives.
    section("GitHub OIDC token (attestation evidence)");
    const ghClaims = decodeJwtPayload(await core.getIDToken("defakto-github"));
    const shown = ["iss", "aud", "sub", "repository", "repository_owner", "ref",
        "workflow_ref", "environment", "event_name", "actor", "runner_environment", "run_id"];
    for (const k of shown) console.log(`  ${k.padEnd(20)} ${ghClaims[k] ?? "(none)"}`);

    const client = new WorkloadAPIClient();

    // 2. X.509-SVID
    section("X.509-SVID issued by Defakto");
    const x509 = await client.x509.getSVID();
    const leaf = x509.certificates[0];
    console.log(`  SPIFFE ID            ${x509.id.toString()}`);
    console.log(`  Subject Alt Name     ${leaf.subjectAltName}`);
    console.log(`  Issuer               ${leaf.issuer.replace(/\n/g, ", ")}`);
    console.log(`  Valid from           ${leaf.validFrom}`);
    console.log(`  Expires              ${x509.expiresAt.toISOString()}`);
    console.log(`  Chain length         ${x509.certificates.length}`);

    // 3. JWT-SVID, validated against the trust domain's JWT bundle
    section("JWT-SVID issued by Defakto");
    const jwt = await client.jwt.fetchSVID([audience]);
    console.log(`  SPIFFE ID            ${jwt.id.toString()}`);
    console.log(`  Audience             ${audience}`);
    console.log(`  Expires              ${jwt.expiresAt.toISOString()}`);
    console.log("  Claims:");
    console.log(JSON.stringify(jwt.claims, null, 2).replace(/^/gm, "    "));

    const verified = await parseAndValidateJwtSVID(jwt.token, client.jwt, [audience]);
    console.log(`  Signature verified   yes (against ${verified.id.trustDomain.toString()} JWT bundle)`);

    section("RESULT");
    console.log(`  SVID ISSUED: ${x509.id.toString()}`);

    summary.push(
        "## Defakto SVID issued",
        "",
        "| | |",
        "|---|---|",
        `| SPIFFE ID | \`${x509.id.toString()}\` |`,
        `| Workflow ref | \`${ghClaims.workflow_ref}\` |`,
        `| X.509 expires | ${x509.expiresAt.toISOString()} |`,
        `| JWT audience | \`${audience}\` |`,
        `| JWT verified | yes |`,
    );
} catch (e) {
    section("RESULT");
    const code = e instanceof SpiffeError ? e.code : e?.name;
    console.log(`  SVID DENIED: ${code}: ${e?.message}`);
    if (e?.cause) console.log(`  cause: ${e.cause?.message ?? e.cause}`);
    summary.push("## Defakto SVID denied", "", `\`${code}: ${e?.message}\``);
    process.exitCode = 1;
} finally {
    if (process.env.GITHUB_STEP_SUMMARY && summary.length) {
        appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary.join("\n") + "\n");
    }
}
