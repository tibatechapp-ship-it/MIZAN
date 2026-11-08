"""Taint analysis — proof-of-concept dataflow tracking (v0.14.0 wave).

Scope (deliberately narrow, per docs/ROADMAP.md P1.2):

  * Python AST only, single file, module-scope name propagation.
  * Two measured source families:
      - input sources: ``input()`` calls and ``sys.argv`` (subscripted or not)
      - request sources: ``request.<attr>`` chains where <attr> is a
        Flask/Django request-data attribute (args, form, values, json, data,
        GET, POST, files, headers, cookies), including method calls on them
        (``request.form.get(...)``).
  * Fixpoint propagation through assignment, ann-assignment, aug-assignment,
    ``for`` targets, and tuple/unary/wrapper expressions (f-strings,
    concatenation, ``str()``, subscripts, attributes, if-expressions,
    boolean operations).

Known PoC limitations (documented, measured before widening):
  * no function-boundary isolation (a name assigned in one function and
    used in another is treated as tainted — such code would not run, so
    the practical FP cost is nil);
  * no interprocedural or cross-module flow;
  * no aliasing of attributes/dict items (only plain names propagate).

This module MUST NOT import analyzer.py (analyzer imports taint).
"""

import ast

# Flask/Django request-data attributes — the values a client controls.
REQUEST_DATA_ATTRS = frozenset({
    "args", "form", "values", "json", "data",
    "GET", "POST", "files", "headers", "cookies",
})

_MAX_FIXPOINT_PASSES = 20


def root_name(node):
    """Root identifier of an attribute chain (``request.form`` -> ``request``)."""
    while isinstance(node, ast.Attribute):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


def is_sys_argv(node):
    """True for ``sys.argv`` expressions (subscripted or not)."""
    if isinstance(node, ast.Subscript):
        node = node.value
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "argv"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def is_input_source(node):
    """True for ``input()`` calls and raw ``sys.argv`` expressions."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
            and node.func.id == "input":
        return True
    return is_sys_argv(node)


def is_request_source(node):
    """True for expressions rooted at ``request`` carrying a data attribute.

    Matches ``request.args``, ``request.form.get("x")``,
    ``request.headers["X"]`` and any longer chain built on them.
    ``request`` alone (e.g. ``request.method``) is NOT a data source.
    """
    seen_attr = False
    while True:
        if isinstance(node, ast.Call):
            node = node.func
            continue
        if isinstance(node, ast.Subscript):
            node = node.value
            continue
        if isinstance(node, ast.Attribute):
            if node.attr in REQUEST_DATA_ATTRS:
                seen_attr = True
            node = node.value
            continue
        if isinstance(node, ast.Name):
            return seen_attr and node.id == "request"
        return False


class TaintSets:
    """Result of propagation: which plain names are tainted by which family."""

    __slots__ = ("input_names", "request_names")

    def __init__(self, input_names, request_names):
        self.input_names = frozenset(input_names)
        self.request_names = frozenset(request_names)


def expr_tainted(node, tainted, source_pred):
    """True if ``node`` references (directly or through wrappers) a tainted
    name or matches the source predicate."""
    if node is None:
        return False
    if source_pred(node):
        return True
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.Call):
        return (
            expr_tainted(node.func, tainted, source_pred)
            or any(expr_tainted(a, tainted, source_pred) for a in node.args)
            or any(expr_tainted(kw.value, tainted, source_pred)
                   for kw in node.keywords)
        )
    if isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
        return expr_tainted(node.value, tainted, source_pred)
    if isinstance(node, ast.JoinedStr):
        return any(expr_tainted(part.value, tainted, source_pred)
                   for part in node.values
                   if isinstance(part, ast.FormattedValue))
    if isinstance(node, ast.BinOp):
        return expr_tainted(node.left, tainted, source_pred) \
            or expr_tainted(node.right, tainted, source_pred)
    if isinstance(node, ast.BoolOp):
        return any(expr_tainted(v, tainted, source_pred) for v in node.values)
    if isinstance(node, ast.IfExp):
        return expr_tainted(node.body, tainted, source_pred) \
            or expr_tainted(node.orelse, tainted, source_pred)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return any(expr_tainted(e, tainted, source_pred) for e in node.elts)
    if isinstance(node, ast.Await):
        return expr_tainted(node.value, tainted, source_pred)
    return False


def _assign_targets(node):
    """Simple Name / tuple-of-Names targets of an assignment-shaped node."""
    targets = []
    if isinstance(node, ast.Assign):
        raw = node.targets
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        raw = [node.target]
    elif isinstance(node, ast.For):
        raw = [node.target]
    else:
        return targets
    for target in raw:
        if isinstance(target, ast.Name):
            targets.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                if isinstance(elt, ast.Name):
                    targets.append(elt.id)
    return targets


def _collect_assignments(tree):
    """(targets, value) pairs for every assignment-shaped node in the file."""
    pairs = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            value = getattr(node, "value", None)
            if value is None:  # AnnAssign without value
                continue
            pairs.append((_assign_targets(node), value))
        elif isinstance(node, ast.For):
            # `for p in <iterable>:` — the iterable is .iter, not .value
            pairs.append((_assign_targets(node), node.iter))
        elif isinstance(node, ast.With):
            # `x = open(...)` style with-bindings: the BINDING carries the
            # taint of the context expression only for plain names — PoC
            # keeps with-bindings out (the source is the call's argument,
            # which the sink checks see directly).
            continue
    return pairs


def propagate(tree, source_pred):
    """Fixpoint: names transitively tainted by ``source_pred`` (file scope)."""
    pairs = _collect_assignments(tree)
    tainted = set()
    for _ in range(_MAX_FIXPOINT_PASSES):
        grew = False
        for targets, value in pairs:
            if not targets:
                continue
            if expr_tainted(value, tainted, source_pred) \
                    and not set(targets) <= tainted:
                tainted.update(targets)
                grew = True
        if not grew:
            break
    return tainted


def collect_taints(tree):
    """Run both source propagations; returns a :class:`TaintSets`."""
    return TaintSets(
        input_names=propagate(tree, is_input_source),
        request_names=propagate(tree, is_request_source),
    )
