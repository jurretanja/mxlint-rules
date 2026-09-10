const metadata = {
    scope: "package",
    title: "Commit actions with a loop",
    description: "Commiting objects within a loop will fire a SQL Update query for each iteration. This applies whether the commit sits directly in the loop or is reached via a called microflow.",
    authors: [
        "Viktor Berlov <viktor@cinaq.com>",
        "Jurre Tanja <jurre.tanja@mendix.com>"
    ],
    custom: {
        category: "Microflows",
        rulename: "AvoidCommitInLoop",
        severity: "MEDIUM",
        rulenumber: "005_0002",
        remediation: "Consider committing objects outside the loop. Within the loop, add them to a list.",
        input: ".*\\$Microflow\\.yaml"
    }
};

function rule(input = {}) {
    const errors = [];

    function collect(node, predicate, acc) {
        acc = acc || [];
        if (!node || typeof node !== "object") return acc;
        if (predicate(node)) acc.push(node);
        for (const key of Object.keys(node)) {
            const v = node[key];
            if (Array.isArray(v)) {
                for (const item of v) collect(item, predicate, acc);
            } else if (v && typeof v === "object") {
                collect(v, predicate, acc);
            }
        }
        return acc;
    }

    const isLoop = n => n["$Type"] === "Microflows$LoopedActivity";

    const isCall = n =>
        n["$Type"] === "Microflows$ActionActivity" &&
        n.Action &&
        n.Action["$Type"] === "Microflows$MicroflowCallAction" &&
        n.Action.MicroflowCall &&
        n.Action.MicroflowCall.Microflow;

    const isCommit = n =>
        n["$Type"] === "Microflows$ActionActivity" &&
        n.Action && (
            n.Action["$Type"] === "Microflows$CommitAction" ||
            (n.Action["$Type"] === "Microflows$ChangeAction" && n.Action.Commit === "Yes") ||
            (n.Action["$Type"] === "Microflows$CreateChangeAction" && n.Action.Commit === "Yes")
        );

    function refToPath(ref) {
        const parts = ref.split(".");
        if (parts.length !== 2) return null;
        return parts[0] + "/" + parts[1] + ".Microflows$Microflow.yaml";
    }

    const pathPrefixes = ["", "rules/005_microflows/", "./rules/005_microflows/"];

    function tryReadYaml(relPath) {
        for (const prefix of pathPrefixes) {
            try {
                const doc = mxlint.io.readYaml(prefix + relPath);
                if (doc) return doc;
            } catch (e) {
                // try next prefix
            }
        }
        return null;
    }

    function commitsTransitively(ref, visited) {
        if (visited.has(ref)) return false;
        visited.add(ref);
        const path = refToPath(ref);
        if (!path) return false;
        const doc = tryReadYaml(path);
        if (!doc) return false;
        if (collect(doc, isCommit).length > 0) return true;
        for (const call of collect(doc, isCall)) {
            if (commitsTransitively(call.Action.MicroflowCall.Microflow, visited)) return true;
        }
        return false;
    }

    const prefix = "[" + metadata.custom.severity + ", " + metadata.custom.category + ", " + metadata.custom.rulenumber + "] ";
    const flowName = input.Name || "unknown";

    const loops = collect(input, isLoop);
    const reportedCommitNodes = new Set();
    const reportedIndirectRefs = new Set();

    for (const loop of loops) {
        for (const c of collect(loop, isCommit)) {
            if (reportedCommitNodes.has(c)) continue;
            reportedCommitNodes.add(c);
            errors.push(prefix + c.Action["$Type"] + " inside " + flowName + " loop");
        }
        for (const call of collect(loop, isCall)) {
            const ref = call.Action.MicroflowCall.Microflow;
            if (reportedIndirectRefs.has(ref)) continue;
            if (commitsTransitively(ref, new Set())) {
                reportedIndirectRefs.add(ref);
                errors.push(prefix + "Microflow " + ref + " called from " + flowName + " loop commits (directly or transitively)");
            }
        }
    }

    return { allow: errors.length === 0, errors };
}
