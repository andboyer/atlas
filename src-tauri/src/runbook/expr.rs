//! Tiny, sandboxed expression evaluator for runbook guards.
//!
//! Grammar (recursive descent):
//!
//! ```text
//!   expr      := or_expr
//!   or_expr   := and_expr ("||" and_expr)*
//!   and_expr  := not_expr ("&&" not_expr)*
//!   not_expr  := "!" not_expr | rel_expr
//!   rel_expr  := add_expr (("=="|"!="|"<"|"<="|">"|">=") add_expr)?
//!              | add_expr "is" ("not")? "null"
//!   add_expr  := mul_expr (("+"|"-") mul_expr)*
//!   mul_expr  := unary    (("*"|"/"|"%") unary)*
//!   unary     := "-" unary | atom
//!   atom      := number | string | bool | "null"
//!              | call | path | "(" expr ")"
//!   call      := IDENT "(" [expr ("," expr)*] ")"
//!   path      := IDENT ("." IDENT | "[" NUMBER "]")*
//! ```
//!
//! Supported call functions:
//!   * `length(x)` — array length, string char count, or 0 for null
//!
//! Special atoms: `null`, `true`, `false`.
//!
//! Path resolution walks a JSON `Value` tree. Missing keys evaluate to
//! `null` (never error) so authoring guards is forgiving. This is critical
//! because not every probe populates every field on every platform.
//!
//! Why hand-rolled instead of an embedded scripting engine: keeps the
//! binary small, eliminates a class of code-execution risk inside
//! user-authored runbooks, and the grammar is small enough to be
//! exhaustively tested in a single file.

use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum ExprError {
    #[error("expression parse error at offset {pos}: {msg}")]
    Parse { msg: String, pos: usize },
    #[error("type error: {0}")]
    Type(String),
    #[error("unknown function: {0}")]
    UnknownFunction(String),
}

/// Evaluate an expression against a JSON binding tree, returning a JSON value.
///
/// `bindings` is the runbook's accumulated step results (the dict whose keys
/// are `bind:` names plus inputs like `nic`).
pub fn eval(expr: &str, bindings: &BTreeMap<String, Value>) -> Result<Value, ExprError> {
    let mut parser = Parser::new(expr);
    let node = parser.parse_expr()?;
    parser.skip_ws();
    if parser.pos < parser.src.len() {
        return Err(ExprError::Parse {
            msg: format!("trailing input: `{}`", &parser.src[parser.pos..]),
            pos: parser.pos,
        });
    }
    eval_node(&node, bindings)
}

/// Convenience: evaluate an expression and coerce to bool.
pub fn eval_bool(expr: &str, bindings: &BTreeMap<String, Value>) -> Result<bool, ExprError> {
    let v = eval(expr, bindings)?;
    Ok(truthy(&v))
}

// ── Template substitution ────────────────────────────────────────────────────

/// Substitute `{path.to.value}` placeholders in a template string with
/// JSON-rendered values from the bindings. Used for `warn_msg`, `on_fail`,
/// and tool-arg string templating.
///
/// Unknown paths render as `<missing>` rather than erroring, so a slightly
/// misnamed key in a message template doesn't crash a runbook.
pub fn render_template(template: &str, bindings: &BTreeMap<String, Value>) -> String {
    let mut out = String::with_capacity(template.len());
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '{' {
            // Find matching '}'
            if let Some(end) = chars[i + 1..].iter().position(|&c| c == '}') {
                let path: String = chars[i + 1..i + 1 + end].iter().collect();
                let path = path.trim();
                if path.is_empty() {
                    out.push('{');
                    out.push('}');
                } else {
                    match resolve_path(path, bindings) {
                        Some(Value::String(s)) => out.push_str(&s),
                        Some(Value::Null) | None => out.push_str("<missing>"),
                        Some(other) => out.push_str(&other.to_string()),
                    }
                }
                i += end + 2;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Public re-export of the dotted/indexed path resolver. Used by the
/// engine's `args` substitution code to preserve typed values when an arg
/// is exactly `"{path}"`.
pub fn resolve_path_pub(path: &str, bindings: &BTreeMap<String, Value>) -> Option<Value> {
    resolve_path(path, bindings)
}

/// Resolve a dotted/indexed path against the bindings dict.
fn resolve_path(path: &str, bindings: &BTreeMap<String, Value>) -> Option<Value> {
    // Tokenise on '.' and '[N]'.
    let mut current: Value = {
        let head = path.split(&['.', '['][..]).next().unwrap_or("");
        bindings.get(head).cloned()?
    };
    let mut rest = &path[path
        .split(&['.', '['][..])
        .next()
        .map(|s| s.len())
        .unwrap_or(0)..];
    while !rest.is_empty() {
        let bytes = rest.as_bytes();
        if bytes[0] == b'.' {
            // Find next dot or bracket.
            let n = rest[1..].find(['.', '[']).unwrap_or(rest.len() - 1);
            let key = &rest[1..1 + n];
            current = current.get(key).cloned().unwrap_or(Value::Null);
            rest = &rest[1 + n..];
        } else if bytes[0] == b'[' {
            let close = rest.find(']')?;
            let idx: usize = rest[1..close].trim().parse().ok()?;
            current = current.get(idx).cloned().unwrap_or(Value::Null);
            rest = &rest[close + 1..];
        } else {
            break;
        }
    }
    Some(current)
}

// ── Node tree ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Node {
    Literal(Value),
    Path(Vec<PathSeg>),
    Call(String, Vec<Node>),
    Neg(Box<Node>),
    Not(Box<Node>),
    Bin(BinOp, Box<Node>, Box<Node>),
    IsNull(Box<Node>, bool /* negated */),
}

#[derive(Debug, Clone)]
enum PathSeg {
    Field(String),
    Index(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinOp {
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    And,
    Or,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

// ── Parser ───────────────────────────────────────────────────────────────────

struct Parser<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, pos: 0 }
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.src[self.pos..].chars().next() {
            if c.is_whitespace() {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn starts_with(&self, s: &str) -> bool {
        self.src[self.pos..].starts_with(s)
    }

    fn consume(&mut self, s: &str) -> bool {
        if self.starts_with(s) {
            self.pos += s.len();
            true
        } else {
            false
        }
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, ExprError> {
        Err(ExprError::Parse {
            msg: msg.into(),
            pos: self.pos,
        })
    }

    fn parse_expr(&mut self) -> Result<Node, ExprError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Node, ExprError> {
        let mut left = self.parse_and()?;
        loop {
            self.skip_ws();
            if self.consume("||") {
                let right = self.parse_and()?;
                left = Node::Bin(BinOp::Or, Box::new(left), Box::new(right));
            } else {
                return Ok(left);
            }
        }
    }

    fn parse_and(&mut self) -> Result<Node, ExprError> {
        let mut left = self.parse_not()?;
        loop {
            self.skip_ws();
            if self.consume("&&") {
                let right = self.parse_not()?;
                left = Node::Bin(BinOp::And, Box::new(left), Box::new(right));
            } else {
                return Ok(left);
            }
        }
    }

    fn parse_not(&mut self) -> Result<Node, ExprError> {
        self.skip_ws();
        if self.starts_with("!=") {
            // Don't gobble the "!" — it's part of the != operator below.
            return self.parse_rel();
        }
        if self.consume("!") {
            let inner = self.parse_not()?;
            return Ok(Node::Not(Box::new(inner)));
        }
        self.parse_rel()
    }

    fn parse_rel(&mut self) -> Result<Node, ExprError> {
        let left = self.parse_add()?;
        self.skip_ws();
        // "is null" / "is not null" suffix
        if self.starts_with("is") {
            // require whitespace after "is" to avoid eating identifiers starting with "is..."
            let after = &self.src[self.pos + 2..];
            if after.starts_with(char::is_whitespace) {
                self.pos += 2;
                self.skip_ws();
                let negated = self.consume("not");
                if negated {
                    self.skip_ws();
                }
                if self.consume("null") {
                    return Ok(Node::IsNull(Box::new(left), negated));
                }
                return self.err("expected `null` after `is` / `is not`");
            }
        }
        let op = if self.consume("==") {
            BinOp::Eq
        } else if self.consume("!=") {
            BinOp::Neq
        } else if self.consume("<=") {
            BinOp::Lte
        } else if self.consume(">=") {
            BinOp::Gte
        } else if self.consume("<") {
            BinOp::Lt
        } else if self.consume(">") {
            BinOp::Gt
        } else {
            return Ok(left);
        };
        let right = self.parse_add()?;
        Ok(Node::Bin(op, Box::new(left), Box::new(right)))
    }

    fn parse_add(&mut self) -> Result<Node, ExprError> {
        let mut left = self.parse_mul()?;
        loop {
            self.skip_ws();
            let op = if self.consume("+") {
                BinOp::Add
            } else if self.starts_with("-") && !self.starts_with("->") {
                self.pos += 1;
                BinOp::Sub
            } else {
                return Ok(left);
            };
            let right = self.parse_mul()?;
            left = Node::Bin(op, Box::new(left), Box::new(right));
        }
    }

    fn parse_mul(&mut self) -> Result<Node, ExprError> {
        let mut left = self.parse_unary()?;
        loop {
            self.skip_ws();
            let op = if self.consume("*") {
                BinOp::Mul
            } else if self.consume("/") {
                BinOp::Div
            } else if self.consume("%") {
                BinOp::Mod
            } else {
                return Ok(left);
            };
            let right = self.parse_unary()?;
            left = Node::Bin(op, Box::new(left), Box::new(right));
        }
    }

    fn parse_unary(&mut self) -> Result<Node, ExprError> {
        self.skip_ws();
        if self.consume("-") {
            let inner = self.parse_unary()?;
            return Ok(Node::Neg(Box::new(inner)));
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> Result<Node, ExprError> {
        self.skip_ws();
        let c = self.peek().ok_or_else(|| ExprError::Parse {
            msg: "unexpected end of input".into(),
            pos: self.pos,
        })?;

        if c == '(' {
            self.pos += 1;
            let inner = self.parse_expr()?;
            self.skip_ws();
            if !self.consume(")") {
                return self.err("expected `)`");
            }
            return Ok(inner);
        }
        if c == '\'' || c == '"' {
            return self.parse_string(c);
        }
        if c.is_ascii_digit() {
            return self.parse_number();
        }
        if c.is_alphabetic() || c == '_' {
            return self.parse_ident_or_call();
        }
        self.err(format!("unexpected character `{c}`"))
    }

    fn parse_string(&mut self, quote: char) -> Result<Node, ExprError> {
        self.pos += 1; // opening quote
        let start = self.pos;
        let chars = self.src[self.pos..].chars();
        for c in chars {
            if c == quote {
                let s = self.src[start..self.pos].to_string();
                self.pos += 1; // closing quote
                return Ok(Node::Literal(Value::String(s)));
            }
            self.pos += c.len_utf8();
        }
        self.err("unterminated string literal")
    }

    fn parse_number(&mut self) -> Result<Node, ExprError> {
        let start = self.pos;
        let mut saw_dot = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.pos += 1;
            } else if c == '.' && !saw_dot {
                saw_dot = true;
                self.pos += 1;
            } else {
                break;
            }
        }
        let text = &self.src[start..self.pos];
        let n: f64 = text.parse().map_err(|_| ExprError::Parse {
            msg: format!("invalid number `{text}`"),
            pos: start,
        })?;
        // Prefer i64 for whole numbers to avoid spurious float coercion.
        if !saw_dot {
            if let Ok(i) = text.parse::<i64>() {
                return Ok(Node::Literal(Value::Number(i.into())));
            }
        }
        Ok(Node::Literal(Value::Number(
            serde_json::Number::from_f64(n).unwrap_or_else(|| 0.into()),
        )))
    }

    fn parse_ident(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        self.src[start..self.pos].to_string()
    }

    fn parse_ident_or_call(&mut self) -> Result<Node, ExprError> {
        let head = self.parse_ident();
        // Keywords
        match head.as_str() {
            "null" => return Ok(Node::Literal(Value::Null)),
            "true" => return Ok(Node::Literal(Value::Bool(true))),
            "false" => return Ok(Node::Literal(Value::Bool(false))),
            _ => {}
        }
        self.skip_ws();
        if self.consume("(") {
            // function call
            let mut args = Vec::new();
            self.skip_ws();
            if !self.consume(")") {
                loop {
                    args.push(self.parse_expr()?);
                    self.skip_ws();
                    if self.consume(",") {
                        continue;
                    }
                    if self.consume(")") {
                        break;
                    }
                    return self.err("expected `,` or `)` in call");
                }
            }
            return Ok(Node::Call(head, args));
        }
        // path
        let mut segs = vec![PathSeg::Field(head)];
        loop {
            if self.consume(".") {
                let f = self.parse_ident();
                if f.is_empty() {
                    return self.err("expected field name after `.`");
                }
                segs.push(PathSeg::Field(f));
            } else if self.consume("[") {
                self.skip_ws();
                let start = self.pos;
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                let idx: usize =
                    self.src[start..self.pos]
                        .parse()
                        .map_err(|_| ExprError::Parse {
                            msg: "expected integer index".into(),
                            pos: start,
                        })?;
                self.skip_ws();
                if !self.consume("]") {
                    return self.err("expected `]`");
                }
                segs.push(PathSeg::Index(idx));
            } else {
                break;
            }
        }
        Ok(Node::Path(segs))
    }
}

// ── Evaluator ────────────────────────────────────────────────────────────────

fn eval_node(node: &Node, bindings: &BTreeMap<String, Value>) -> Result<Value, ExprError> {
    Ok(match node {
        Node::Literal(v) => v.clone(),
        Node::Path(segs) => walk_path(segs, bindings),
        Node::Call(name, args) => {
            let vs: Vec<Value> = args
                .iter()
                .map(|a| eval_node(a, bindings))
                .collect::<Result<_, _>>()?;
            call_fn(name, &vs)?
        }
        Node::Neg(inner) => {
            let v = eval_node(inner, bindings)?;
            match v {
                Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        Value::Number((-i).into())
                    } else if let Some(f) = n.as_f64() {
                        Value::Number(serde_json::Number::from_f64(-f).unwrap_or_else(|| 0.into()))
                    } else {
                        Value::Null
                    }
                }
                Value::Null => Value::Null,
                _ => return Err(ExprError::Type("unary `-` on non-number".into())),
            }
        }
        Node::Not(inner) => {
            let v = eval_node(inner, bindings)?;
            Value::Bool(!truthy(&v))
        }
        Node::IsNull(inner, negated) => {
            let v = eval_node(inner, bindings)?;
            let is_null = matches!(v, Value::Null);
            Value::Bool(if *negated { !is_null } else { is_null })
        }
        Node::Bin(op, l, r) => {
            // Short-circuit for and/or.
            match op {
                BinOp::And => {
                    let lv = eval_node(l, bindings)?;
                    if !truthy(&lv) {
                        return Ok(Value::Bool(false));
                    }
                    return Ok(Value::Bool(truthy(&eval_node(r, bindings)?)));
                }
                BinOp::Or => {
                    let lv = eval_node(l, bindings)?;
                    if truthy(&lv) {
                        return Ok(Value::Bool(true));
                    }
                    return Ok(Value::Bool(truthy(&eval_node(r, bindings)?)));
                }
                _ => {}
            }
            let lv = eval_node(l, bindings)?;
            let rv = eval_node(r, bindings)?;
            apply_bin(*op, &lv, &rv)?
        }
    })
}

fn walk_path(segs: &[PathSeg], bindings: &BTreeMap<String, Value>) -> Value {
    let mut current = match &segs[0] {
        PathSeg::Field(f) => bindings.get(f).cloned().unwrap_or(Value::Null),
        PathSeg::Index(_) => Value::Null,
    };
    for seg in &segs[1..] {
        current = match seg {
            PathSeg::Field(f) => current.get(f).cloned().unwrap_or(Value::Null),
            PathSeg::Index(i) => current.get(*i).cloned().unwrap_or(Value::Null),
        };
    }
    current
}

fn call_fn(name: &str, args: &[Value]) -> Result<Value, ExprError> {
    match name {
        "length" => {
            if args.len() != 1 {
                return Err(ExprError::Type(format!(
                    "length() expects 1 arg, got {}",
                    args.len()
                )));
            }
            Ok(match &args[0] {
                Value::Array(a) => Value::Number((a.len() as i64).into()),
                Value::String(s) => Value::Number((s.chars().count() as i64).into()),
                Value::Object(o) => Value::Number((o.len() as i64).into()),
                Value::Null => Value::Number(0.into()),
                _ => return Err(ExprError::Type("length() on non-collection".into())),
            })
        }
        _ => Err(ExprError::UnknownFunction(name.into())),
    }
}

fn apply_bin(op: BinOp, l: &Value, r: &Value) -> Result<Value, ExprError> {
    use BinOp::*;
    match op {
        Eq => Ok(Value::Bool(json_eq(l, r))),
        Neq => Ok(Value::Bool(!json_eq(l, r))),
        Lt | Lte | Gt | Gte => {
            let (ln, rn) = (to_f64(l), to_f64(r));
            match (ln, rn) {
                (Some(a), Some(b)) => Ok(Value::Bool(match op {
                    Lt => a < b,
                    Lte => a <= b,
                    Gt => a > b,
                    Gte => a >= b,
                    _ => unreachable!(),
                })),
                _ => Ok(Value::Bool(false)),
            }
        }
        Add | Sub | Mul | Div | Mod => {
            // Number+number arithmetic; string concat for Add+strings.
            if op == Add {
                if let (Value::String(a), Value::String(b)) = (l, r) {
                    return Ok(Value::String(format!("{a}{b}")));
                }
            }
            let (a, b) = (
                to_f64(l).ok_or_else(|| ExprError::Type("arithmetic on non-number".into()))?,
                to_f64(r).ok_or_else(|| ExprError::Type("arithmetic on non-number".into()))?,
            );
            let v = match op {
                Add => a + b,
                Sub => a - b,
                Mul => a * b,
                Div => {
                    if b == 0.0 {
                        return Ok(Value::Null);
                    }
                    a / b
                }
                Mod => {
                    if b == 0.0 {
                        return Ok(Value::Null);
                    }
                    a % b
                }
                _ => unreachable!(),
            };
            // Preserve integer type when both operands are ints and the
            // result is a whole number (so `a + b` returns Number(13) not
            // Number(13.0) — matters for downstream JSON consumers).
            let both_int = matches!((l, r), (Value::Number(a), Value::Number(b))
                if a.is_i64() && b.is_i64());
            if both_int && v.fract() == 0.0 && v.is_finite() {
                return Ok(Value::Number(serde_json::Number::from(v as i64)));
            }
            Ok(Value::Number(
                serde_json::Number::from_f64(v).unwrap_or_else(|| 0.into()),
            ))
        }
        And | Or => unreachable!("short-circuited above"),
    }
}

fn json_eq(l: &Value, r: &Value) -> bool {
    match (l, r) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Number(_), Value::Number(_)) => {
            // Compare as f64 so `1 == 1.0` works.
            to_f64(l) == to_f64(r)
        }
        _ => l == r,
    }
}

fn to_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::Bool(true) => Some(1.0),
        Value::Bool(false) => Some(0.0),
        Value::Null => None,
        _ => None,
    }
}

/// Truthiness used by `&&`, `||`, `!`, and the engine's guard checks.
/// `null`, `false`, `0`, `""`, `[]`, `{}` are falsy; everything else is truthy.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|x| x != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binds(json_val: serde_json::Value) -> BTreeMap<String, Value> {
        let mut b = BTreeMap::new();
        if let serde_json::Value::Object(map) = json_val {
            for (k, v) in map {
                b.insert(k, v);
            }
        }
        b
    }

    #[test]
    fn literals() {
        let b = binds(json!({}));
        assert_eq!(eval("42", &b).unwrap(), json!(42));
        assert_eq!(eval("1.5", &b).unwrap(), json!(1.5));
        assert_eq!(eval("'hi'", &b).unwrap(), json!("hi"));
        assert_eq!(eval("\"hi\"", &b).unwrap(), json!("hi"));
        assert_eq!(eval("true", &b).unwrap(), json!(true));
        assert_eq!(eval("false", &b).unwrap(), json!(false));
        assert_eq!(eval("null", &b).unwrap(), json!(null));
    }

    #[test]
    fn comparisons() {
        let b = binds(json!({"link": {"speed_mbps": 10, "duplex": "half"}}));
        assert!(eval_bool("link.speed_mbps < 100", &b).unwrap());
        assert!(eval_bool("link.speed_mbps != 100", &b).unwrap());
        assert!(eval_bool("link.duplex == 'half'", &b).unwrap());
        assert!(eval_bool("link.duplex != 'full'", &b).unwrap());
        assert!(!eval_bool("link.speed_mbps >= 100", &b).unwrap());
        assert!(eval_bool("link.speed_mbps == 10", &b).unwrap());
        // numeric equality across int/float
        assert!(eval_bool("link.speed_mbps == 10.0", &b).unwrap());
    }

    #[test]
    fn logical() {
        let b = binds(json!({"x": 5, "y": null}));
        assert!(eval_bool("x > 3 && x < 10", &b).unwrap());
        assert!(eval_bool("x > 100 || x < 10", &b).unwrap());
        assert!(eval_bool("!(x > 100)", &b).unwrap());
        // short circuit — missing.field would explode if not short-circuited
        assert!(!eval_bool("y is not null && y.missing.field > 0", &b).unwrap());
    }

    #[test]
    fn is_null() {
        let b = binds(json!({"a": 1, "b": null}));
        assert!(eval_bool("b is null", &b).unwrap());
        assert!(eval_bool("a is not null", &b).unwrap());
        assert!(eval_bool("missing is null", &b).unwrap()); // missing -> null
    }

    #[test]
    fn length() {
        let b = binds(json!({
            "arr": [1,2,3],
            "str": "hello",
            "obj": {"a":1, "b":2},
            "n": null,
        }));
        assert_eq!(eval("length(arr)", &b).unwrap(), json!(3));
        assert_eq!(eval("length(str)", &b).unwrap(), json!(5));
        assert_eq!(eval("length(obj)", &b).unwrap(), json!(2));
        assert_eq!(eval("length(n)", &b).unwrap(), json!(0));
        assert!(eval_bool("length(arr) > 0", &b).unwrap());
    }

    #[test]
    fn path_indexing() {
        let b = binds(json!({"qs": {"queriers_seen": [{"ip":"10.0.0.1"}, {"ip":"10.0.0.2"}]}}));
        assert_eq!(
            eval("qs.queriers_seen[0].ip", &b).unwrap(),
            json!("10.0.0.1")
        );
        assert!(eval_bool("length(qs.queriers_seen) > 1", &b).unwrap());
    }

    #[test]
    fn arithmetic() {
        let b = binds(json!({"a": 10, "b": 3}));
        assert_eq!(eval("a + b", &b).unwrap(), json!(13));
        assert_eq!(eval("a - b", &b).unwrap(), json!(7));
        assert_eq!(eval("a * b", &b).unwrap(), json!(30));
        assert_eq!(eval("a / b", &b).unwrap().as_f64().unwrap() as i64, 3);
        assert_eq!(eval("a % b", &b).unwrap().as_f64().unwrap() as i64, 1);
        // div by zero -> null (no panic)
        assert_eq!(eval("a / 0", &b).unwrap(), json!(null));
    }

    #[test]
    fn templates() {
        let b = binds(json!({
            "link": {"speed_mbps": 100, "duplex": "full"},
            "dscp": {"value": 0},
        }));
        assert_eq!(
            render_template("DSCP is {dscp.value}, expected 46", &b),
            "DSCP is 0, expected 46"
        );
        assert_eq!(
            render_template("Link {link.duplex} at {link.speed_mbps}M", &b),
            "Link full at 100M"
        );
        assert_eq!(
            render_template("missing: {does.not.exist}", &b),
            "missing: <missing>"
        );
    }

    #[test]
    fn realistic_runbook_guards() {
        // These exactly mirror guards used in shipped runbooks below.
        let b = binds(json!({
            "link": {"speed_mbps": 100, "duplex": "full"},
            "dante": {"devices": [{"name":"A"}, {"name":"B"}]},
            "ptp": {"classification": "stable_gm"},
            "igmp": {"queriers_seen": []},
            "dscp": {"value": 46},
        }));
        assert!(!eval_bool("link.duplex != 'full' || link.speed_mbps < 100", &b).unwrap());
        assert!(!eval_bool("length(dante.devices) == 0", &b).unwrap());
        assert!(!eval_bool("ptp.classification == 'multiple_gms'", &b).unwrap());
        assert!(eval_bool("length(igmp.queriers_seen) == 0", &b).unwrap());
        assert!(!eval_bool("dscp.value != 46", &b).unwrap());
    }
}
