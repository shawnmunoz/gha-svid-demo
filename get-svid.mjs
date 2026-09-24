// Runs inside a GitHub Actions job and prints the X.509 and JWT SVIDs Defakto
// issues for it. Two modes, picked from the environment:
//
// Serverless (GitHub-hosted runners): attests straight to Defakto's endpoint
// with the job's GitHub OIDC token. No agent, no secrets.
//   DEFAKTO_ATTESTORS=github
//   DEFAKTO_TRUST_DOMAIN_ID=td-...
//
// Agent (self-hosted runners with a Defakto agent): SPIFFE_ENDPOINT_SOCKET is
// injected into the runner pod. The job sends its GitHub OIDC token (audience
// https://spirl.com) to the local agent as an identity-exchange token. The
// agent verifies it using the cluster's linked "github-actions" CI/CD profile.
//
// Both modes:
//   SVID_AUDIENCE=<audience for the JWT-SVID>
import { appendFileSync } from "node:fs";
import * as core from "@actions/core";
import {
    WorkloadAPIClient, LocalWorkloadAPIClient, SpiffeError, parseAndValidateJwtSVID,
} from "@defakto/spiffe";

const audience = process.env.SVID_AUDIENCE ?? "github-actions-demo";
const agentMode = !!process.env.SPIFFE_ENDPOINT_SOCKET;
// The agent's JWT attestor only accepts identity-exchange tokens with this audience.
const AGENT_TOKEN_AUDIENCE = "https://spirl.com";
const summary = [];

function section(title) {
    console.log(`\n==================== ${title} ====================`);
}

function decodeJwtPayload(token) {
    return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
}

try {
    // 1. What GitHub vouches for. In serverless mode the GithubAttestor fetches
    //    this same token itself; we decode a copy only to show what Defakto
    //    receives. In agent mode we send it to the agent ourselves.
    section(`GitHub OIDC token (attestation evidence, ${agentMode ? "sent to the local Defakto agent" : "sent to Defakto serverless"})`);
    let ghToken = null;
    try {
        ghToken = await core.getIDToken(agentMode ? AGENT_TOKEN_AUDIENCE : "defakto-github");
    } catch (e) {
        if (!agentMode) throw e;
        // No id-token permission: the job has nothing to prove it is a GitHub
        // Actions job, and asks the agent anyway.
        console.log(`  (no token: ${e.message.split("\n")[0]})`);
    }
    const ghClaims = ghToken ? decodeJwtPayload(ghToken) : {};
    if (ghToken) {
        const shown = ["iss", "aud", "sub", "repository", "repository_owner", "ref",
            "workflow_ref", "environment", "event_name", "actor", "runner_environment", "run_id"];
        for (const k of shown) console.log(`  ${k.padEnd(20)} ${ghClaims[k] ?? "(none)"}`);
    }

    const client = agentMode
        ? new LocalWorkloadAPIClient(ghToken ? { headers: { "identity-exchange-token": ghToken } } : undefined)
        : new WorkloadAPIClient();
    if (agentMode) console.log(`\n  Defakto agent socket ${process.env.SPIFFE_ENDPOINT_SOCKET}`);

    // 2. X.509-SVID
    section(`Requesting X.509-SVID from ${agentMode ? "the Defakto agent" : "Defakto"}`);
    const x509 = await client.x509.getSVID();
    const leaf = x509.certificates[0];
    console.log(`  SPIFFE ID            ${x509.id.toString()}`);
    console.log(`  Subject Alt Name     ${leaf.subjectAltName}`);
    console.log(`  Issuer               ${leaf.issuer.replace(/\n/g, ", ")}`);
    console.log(`  Valid from           ${leaf.validFrom}`);
    console.log(`  Expires              ${x509.expiresAt.toISOString()}`);
    console.log(`  Chain length         ${x509.certificates.length}`);

    // 3. JWT-SVID, validated against the trust domain's JWT bundle
    section(`Requesting JWT-SVID from ${agentMode ? "the Defakto agent" : "Defakto"}`);
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
        `| Issued via | ${agentMode ? "Defakto agent (CI/CD profile)" : "Defakto serverless"} |`,
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
