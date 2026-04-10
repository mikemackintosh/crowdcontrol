/*
 * Parser for CrowdControl policy source.
 *
 * Ports github.com/mikemackintosh/crowdcontrol/parser/parser.go to Kotlin.
 */
package io.github.mikemackintosh.crowdcontrol

/** Parse CrowdControl source into a Policy AST. */
fun parse(source: String): Policy {
    val tokens = lex(source)
    return Parser(tokens).parsePolicy()
}

internal class Parser(private val tokens: List<Token>) {
    private var pos: Int = 0

    // ----- top level -------------------------------------------------------

    fun parsePolicy(): Policy {
        val policy = Policy()
        while (!atEnd()) {
            policy.rules.add(parseRule())
        }
        return policy
    }

    private fun parseRule(): Rule {
        val kindTok = advance()
        if (kindTok.type != TokenType.IDENT) {
            throw errorf("expected forbid, warn, or permit, got $kindTok")
        }
        val kind = kindTok.value
        if (kind != "forbid" && kind != "warn" && kind != "permit") {
            throw errorf("expected forbid, warn, or permit, got \"$kind\"")
        }

        val nameTok = advance()
        if (nameTok.type != TokenType.STRING) {
            throw errorf("expected rule name string, got $nameTok")
        }

        expect(TokenType.LBRACE)

        val rule = Rule(kind = kind, name = nameTok.value)

        while (!check(TokenType.RBRACE) && !atEnd()) {
            parseClause(rule)
        }

        expect(TokenType.RBRACE)
        return rule
    }

    private fun parseClause(rule: Rule) {
        val tok = peek()
        val v = tok.value

        if (v == "unless") {
            parseUnless(rule)
            return
        }
        if (v == "message") {
            parseMessage(rule)
            return
        }
        if (v == "description" || v == "owner" || v == "link") {
            parseMetadata(rule, v)
            return
        }
        val cond: Condition = when (v) {
            "not" -> parseNegatedCondition()
            "any", "all" -> parseQuantifier()
            "has" -> parseHasCondition()
            "count" -> parseAggregateCondition()
            "lower", "upper", "len" -> parseTransformCondition()
            else -> parseFieldCond()
        }

        rule.conditions.add(wrapOr(cond))
    }

    // ----- or-chaining -----------------------------------------------------

    private fun wrapOr(first: Condition): Condition {
        if (!checkIdent("or")) return first
        val group = mutableListOf(first)
        while (checkIdent("or")) {
            advance() // consume "or"
            val cond = try {
                parseSingleCondition()
            } catch (_: ParseError) {
                break
            }
            group.add(cond)
        }
        return Condition(type = ConditionType.OR, orGroup = group)
    }

    private fun parseSingleCondition(): Condition {
        val v = peek().value
        return when (v) {
            "not" -> parseNegatedCondition()
            "any", "all" -> parseQuantifier()
            "has" -> parseHasCondition()
            "count" -> parseAggregateCondition()
            "lower", "upper", "len" -> parseTransformCondition()
            else -> parseFieldCond()
        }
    }

    // ----- individual conditions -------------------------------------------

    private fun parseNegatedCondition(): Condition {
        advance() // consume "not"
        val cond = parseSingleCondition()
        cond.negated = !cond.negated
        return cond
    }

    private fun parseHasCondition(): Condition {
        advance() // consume "has"
        val field = parseDottedPath()
        return Condition(type = ConditionType.HAS, field = field)
    }

    private fun parseQuantifier(): Condition {
        val quantTok = advance() // consume "any" or "all"
        val listField = parseDottedPath()
        val predicate = parseElementPredicate()
        val condType = if (quantTok.value == "all") ConditionType.ALL else ConditionType.ANY
        return Condition(
            type = condType,
            quantifier = quantTok.value,
            listField = listField,
            predicate = predicate,
        )
    }

    private fun parseElementPredicate(): Condition {
        val tok = peek()

        if (tok.type == TokenType.IDENT && tok.value == "in") {
            advance()
            val nxt = peek()
            if (nxt.type == TokenType.LBRACKET) {
                val vals = parseStringList()
                return Condition(type = ConditionType.FIELD, op = "in", value = vals)
            }
            throw errorf("expected list after 'in', got $nxt")
        }

        if (tok.type == TokenType.IDENT && (tok.value == "matches" || tok.value == "matches_regex")) {
            val op = tok.value
            advance()
            val valTok = advance()
            if (valTok.type != TokenType.STRING) {
                throw errorf("$op expects a string pattern, got $valTok")
            }
            return Condition(type = ConditionType.FIELD, op = op, value = valTok.value)
        }

        if (tok.type == TokenType.IDENT && tok.value == "contains") {
            advance()
            val v = parseValue()
            return Condition(type = ConditionType.FIELD, op = "contains", value = v)
        }

        val opTok = advance()
        if (opTok.type !in COMPARISON_TOKENS) {
            throw errorf("expected operator in quantifier predicate, got $opTok")
        }
        val v = parseValue()
        return Condition(type = ConditionType.FIELD, op = opTok.value, value = v)
    }

    private fun parseFieldCond(): Condition {
        val field = parseDottedPath()

        if (isArithOp()) {
            val left = Expr(kind = ExprKind.FIELD, field = field)
            return parseExprConditionFromLeft(left)
        }

        val opTok = advance()
        var op = opTok.value

        if (opTok.type !in COMPARISON_TOKENS) {
            if (opTok.type == TokenType.IDENT && opTok.value in KEYWORD_OPS) {
                op = opTok.value
            } else {
                throw errorf("expected operator, got $opTok")
            }
        }

        val cond = Condition(type = ConditionType.FIELD, field = field, op = op)

        when (op) {
            "in", "intersects", "is_subset" -> cond.value = parseStringList()
            "matches", "matches_regex" -> {
                val valTok = advance()
                if (valTok.type != TokenType.STRING) {
                    throw errorf("$op expects a string pattern, got $valTok")
                }
                cond.value = valTok.value
            }
            else -> cond.value = parseValue()
        }

        return cond
    }

    private fun isArithOp(): Boolean {
        val t = peek().type
        return t == TokenType.PLUS || t == TokenType.MINUS ||
            t == TokenType.STAR || t == TokenType.SLASH
    }

    private fun parseExprConditionFromLeft(left: Expr): Condition {
        val leftExpr = parseArithExprFrom(left)

        val opTok = advance()
        if (opTok.type !in COMPARISON_TOKENS) {
            throw errorf("expected comparison operator in expression, got $opTok")
        }

        val rightExpr = parseArithExpr()
        return Condition(
            type = ConditionType.EXPR,
            op = opTok.value,
            leftExpr = leftExpr,
            rightExpr = rightExpr,
        )
    }

    private fun parseArithExpr(): Expr {
        val left = parseExprTerm()
        return parseArithExprFrom(left)
    }

    private fun parseArithExprFrom(initial: Expr): Expr {
        var left = initial
        while (isArithOp()) {
            val opTok = advance()
            val right = parseExprTerm()
            left = Expr(kind = ExprKind.BINARY, op = opTok.value, left = left, right = right)
        }
        return left
    }

    private fun parseExprTerm(): Expr {
        val tok = peek()

        if (tok.type == TokenType.NUMBER) {
            advance()
            val num = tok.value.toDoubleOrNull()
                ?: throw errorf("invalid number: ${tok.value}")
            return Expr(kind = ExprKind.LITERAL, value = num)
        }

        if (tok.type == TokenType.IDENT && (tok.value == "count" || tok.value == "len")) {
            val funcName = tok.value
            advance()
            expect(TokenType.LPAREN)
            val path = parseDottedPath()
            expect(TokenType.RPAREN)
            return if (funcName == "count") {
                Expr(kind = ExprKind.COUNT, aggTarget = path)
            } else {
                Expr(kind = ExprKind.LEN, field = path, transform = "len")
            }
        }

        if (tok.type == TokenType.IDENT) {
            val path = parseDottedPath()
            return Expr(kind = ExprKind.FIELD, field = path)
        }

        throw errorf("expected number, field, count(), or len() in expression, got $tok")
    }

    private fun parseUnless(rule: Rule) {
        advance() // consume "unless"
        val v = peek().value
        val cond: Condition = when (v) {
            "not" -> parseNegatedCondition()
            "any", "all" -> parseQuantifier()
            "has" -> parseHasCondition()
            "lower", "upper", "len" -> parseTransformCondition()
            "count" -> parseAggregateCondition()
            else -> parseFieldCond()
        }
        rule.unlesses.add(cond)
    }

    private fun parseTransformCondition(): Condition {
        val funcTok = advance()
        expect(TokenType.LPAREN)
        val field = parseDottedPath()
        expect(TokenType.RPAREN)

        if (funcTok.value == "len" && isArithOp()) {
            val left = Expr(kind = ExprKind.LEN, field = field, transform = "len")
            return parseExprConditionFromLeft(left)
        }

        val opTok = advance()
        var op = opTok.value
        if (opTok.type !in COMPARISON_TOKENS) {
            if (opTok.type == TokenType.IDENT && opTok.value in setOf("in", "matches", "matches_regex", "contains")) {
                op = opTok.value
            } else {
                throw errorf("expected operator after ${funcTok.value}(), got $opTok")
            }
        }

        val cond = Condition(type = ConditionType.FIELD, field = field, op = op, transform = funcTok.value)

        when (op) {
            "in" -> cond.value = parseStringList()
            "matches", "matches_regex" -> {
                val valTok = advance()
                if (valTok.type != TokenType.STRING) {
                    throw errorf("$op expects a string pattern, got $valTok")
                }
                cond.value = valTok.value
            }
            else -> cond.value = parseValue()
        }
        return cond
    }

    private fun parseAggregateCondition(): Condition {
        advance() // consume "count"
        expect(TokenType.LPAREN)
        val target = parseDottedPath()
        expect(TokenType.RPAREN)

        if (isArithOp()) {
            val left = Expr(kind = ExprKind.COUNT, aggTarget = target)
            return parseExprConditionFromLeft(left)
        }

        val opTok = advance()
        if (opTok.type !in COMPARISON_TOKENS) {
            throw errorf("expected comparison operator after count(), got $opTok")
        }

        val valTok = advance()
        if (valTok.type != TokenType.NUMBER) {
            throw errorf("expected number after operator, got $valTok")
        }
        val num = valTok.value.toIntOrNull()
            ?: throw errorf("invalid number: ${valTok.value}")

        return Condition(
            type = ConditionType.AGGREGATE,
            aggregateFunc = "count",
            aggregateTarget = target,
            op = opTok.value,
            value = num,
        )
    }

    private fun parseMessage(rule: Rule) {
        advance()
        val msgTok = advance()
        if (msgTok.type != TokenType.STRING) {
            throw errorf("expected message string, got $msgTok")
        }
        rule.message = msgTok.value
    }

    private fun parseMetadata(rule: Rule, keyword: String) {
        advance()
        val valTok = advance()
        if (valTok.type != TokenType.STRING) {
            throw errorf("expected string after $keyword, got $valTok")
        }
        when (keyword) {
            "description" -> rule.description = valTok.value
            "owner" -> rule.owner = valTok.value
            "link" -> rule.link = valTok.value
        }
    }

    // ----- helpers ---------------------------------------------------------

    private fun parseDottedPath(): String {
        val tok = advance()
        if (tok.type != TokenType.IDENT) {
            throw errorf("expected identifier, got $tok")
        }
        val parts = mutableListOf(tok.value)
        while (check(TokenType.DOT)) {
            advance()
            val nxt = advance()
            if (nxt.type != TokenType.IDENT) {
                throw errorf("expected identifier after '.', got $nxt")
            }
            parts.add(nxt.value)
        }
        return parts.joinToString(".")
    }

    private fun parseStringList(): List<String> {
        expect(TokenType.LBRACKET)
        val vals = mutableListOf<String>()
        while (!check(TokenType.RBRACKET) && !atEnd()) {
            val tok = advance()
            if (tok.type != TokenType.STRING) {
                throw errorf("expected string in list, got $tok")
            }
            vals.add(tok.value)
            if (check(TokenType.COMMA)) advance()
        }
        expect(TokenType.RBRACKET)
        return vals
    }

    private fun parseValue(): Any {
        val tok = advance()
        when (tok.type) {
            TokenType.STRING -> return tok.value
            TokenType.NUMBER -> {
                // Prefer Long/Int for integer-valued numbers, Double otherwise.
                return if ('.' in tok.value) {
                    tok.value.toDoubleOrNull()
                        ?: throw errorf("invalid number: ${tok.value}")
                } else {
                    tok.value.toLongOrNull()?.let { l ->
                        // Fit in Int if possible for parity with other ports.
                        if (l in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) l.toInt() else l
                    } ?: tok.value.toDoubleOrNull()
                        ?: throw errorf("invalid number: ${tok.value}")
                }
            }
            TokenType.IDENT -> {
                return when (tok.value) {
                    "true" -> true
                    "false" -> false
                    else -> throw errorf("unexpected identifier \"${tok.value}\" in value position")
                }
            }
            else -> throw errorf("expected value, got $tok")
        }
    }

    private fun peek(): Token {
        if (pos >= tokens.size) return Token(TokenType.EOF)
        return tokens[pos]
    }

    private fun advance(): Token {
        val tok = peek()
        if (tok.type != TokenType.EOF) pos += 1
        return tok
    }

    private fun check(t: TokenType): Boolean = peek().type == t

    private fun checkIdent(v: String): Boolean {
        val tok = peek()
        return tok.type == TokenType.IDENT && tok.value == v
    }

    private fun atEnd(): Boolean = peek().type == TokenType.EOF

    private fun expect(t: TokenType): Token {
        val tok = advance()
        if (tok.type != t) throw errorf("expected ${t.name}, got $tok")
        return tok
    }

    private fun errorf(msg: String): ParseError {
        val tok = peek()
        return ParseError("line ${tok.line} col ${tok.col}: $msg")
    }

    companion object {
        private val COMPARISON_TOKENS = setOf(
            TokenType.EQ, TokenType.NEQ,
            TokenType.LT, TokenType.GT,
            TokenType.LTE, TokenType.GTE,
        )
        private val KEYWORD_OPS = setOf(
            "in", "matches", "matches_regex",
            "contains", "intersects", "is_subset",
        )
    }
}
