# v0.17.0-dev wave 1 reclassification (field-measured, not guessed).
# The nexus-core PR #95 evidence scan (report digest 07af33c5..., scan
# commit 1371c54) measured 5/5 production sites of bare compile()
# inside try/except SyntaxError as pure syntax checks — compile() never
# executes its argument, so the compile-as-value shape stopped firing.
# The positive that REMAINS is the consumed idiom: the compiled code
# object handed to exec(), where the bare exec() call is what fires.
def run_dynamic_config(src):
    exec(compile(src, "<cfg>", "exec"))
