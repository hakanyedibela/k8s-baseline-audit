import json

from k8s_baseline_audit.collect.runner import CommandResult

TEMPLATE_KINDS = {"secrets"}


class FakeKubectl:
    """Answers the collector's kubectl calls from in-memory data."""

    def __init__(self, get=None, forbidden=(), version=None, context="kind-test",
                 server="https://127.0.0.1:6443", can_i_failures=None):
        self.get = get or {}  # kind -> (exit_code, stdout)
        self.forbidden = set(forbidden)
        self.version = version or {"serverVersion": {"major": "1", "minor": "35"}}
        self.context = context
        self.server = server
        self.calls = []
        self.can_i_failures = can_i_failures or {}  # kind -> (exit_code, stdout, stderr)

    def __call__(self, argv):
        args = list(argv[1:])
        if args[:1] == ["--context"]:
            args = args[2:]
        self.calls.append(args)
        verb = args[0]

        def ok(out, code=0, err=""):
            return CommandResult(tuple(argv), code, out, err)

        if verb == "config":
            return ok(self.context if args[1] == "current-context" else self.server)
        if verb == "version":
            return ok(json.dumps(self.version))
        if verb == "auth":
            kind = args[3]
            if kind in self.can_i_failures:
                code, stdout, stderr = self.can_i_failures[kind]
                return CommandResult(tuple(argv), code, stdout, stderr)
            return ok("no\n", 1) if kind in self.forbidden else ok("yes\n")
        if verb == "get":
            kind = args[1]
            default = (0, "") if kind in TEMPLATE_KINDS else (0, json.dumps({"items": []}))
            code, out = self.get.get(kind, default)
            return ok(out, code, "" if code == 0 else "Error from server (InternalError)")
        raise AssertionError(f"unexpected kubectl call: {args}")
