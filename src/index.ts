import { PolicyPack } from "@pulumi/policy";
import { validateByType, Finding } from "./validators";

function report(findings: Finding[], reportViolation: (message: string) => void): void {
    for (const f of findings) {
        reportViolation(`[${f.rule}] ${f.message}`);
    }
}

// CrossGuard pack mirroring the operator's admission webhook. Evaluated at
// `pulumi preview` (local — no operator round-trip). The same accept/reject
// verdicts the admission webhook would produce must hold here (the shared
// contract corpus under iac/contract/).
new PolicyPack("mcpg-admission-mirror", {
    policies: [
        {
            name: "mcpg-admission-mirror",
            description: "Mirror the MCPG operator's CRD admission rules at preview time.",
            enforcementLevel: "mandatory",
            validateResource: (args, reportViolation) => {
                const spec = (args.props as any)?.spec;
                report(validateByType(args.type, spec), reportViolation);
            },
        },
    ],
});
