package parser

import (
	"fmt"
	"strconv"

	"github.com/mikemackintosh/crowdcontrol/types"
)

// Parser turns a token stream into a CrowdControl Policy AST.
type Parser struct {
	tokens []Token
	pos    int
}

// Parse parses CrowdControl policy source into a Policy.
func Parse(source string) (*types.Policy, error) {
	tokens, err := Lex(source)
	if err != nil {
		return nil, err
	}

	p := &Parser{tokens: tokens}
	return p.parsePolicy()
}

func (p *Parser) parsePolicy() (*types.Policy, error) {
	policy := &types.Policy{}

	for !p.atEnd() {
		rule, err := p.parseRule()
		if err != nil {
			return nil, err
		}
		policy.Rules = append(policy.Rules, rule)
	}

	return policy, nil
}

func (p *Parser) parseRule() (types.Rule, error) {
	// Expect: forbid|warn|permit "name" { ... }
	kindTok := p.advance()
	if kindTok.Type != TokenIdent {
		return types.Rule{}, p.errorf("expected forbid, warn, or permit, got %s", kindTok)
	}

	kind := kindTok.Val
	if kind != "forbid" && kind != "warn" && kind != "permit" {
		return types.Rule{}, p.errorf("expected forbid, warn, or permit, got %q", kind)
	}

	nameTok := p.advance()
	if nameTok.Type != TokenString {
		return types.Rule{}, p.errorf("expected rule name string, got %s", nameTok)
	}

	if err := p.expect(TokenLBrace); err != nil {
		return types.Rule{}, err
	}

	rule := types.Rule{
		Kind: kind,
		Name: nameTok.Val,
	}

	// Parse body until }
	for !p.check(TokenRBrace) && !p.atEnd() {
		if err := p.parseClause(&rule); err != nil {
			return types.Rule{}, err
		}
	}

	if err := p.expect(TokenRBrace); err != nil {
		return types.Rule{}, err
	}

	return rule, nil
}

func (p *Parser) parseClause(rule *types.Rule) error {
	tok := p.peek()

	switch tok.Val {
	case "unless":
		return p.parseUnless(rule)
	case "message":
		return p.parseMessage(rule)
	case "description":
		return p.parseMetadata(rule, "description")
	case "owner":
		return p.parseMetadata(rule, "owner")
	case "link":
		return p.parseMetadata(rule, "link")
	case "not":
		cond, err := p.parseNegatedCondition()
		if err != nil {
			return err
		}
		rule.Conditions = append(rule.Conditions, p.wrapOr(cond))
		return nil
	case "any", "all":
		cond, err := p.parseQuantifier()
		if err != nil {
			return err
		}
		rule.Conditions = append(rule.Conditions, p.wrapOr(cond))
		return nil
	case "has":
		cond, err := p.parseHasCondition()
		if err != nil {
			return err
		}
		rule.Conditions = append(rule.Conditions, p.wrapOr(cond))
		return nil
	case "count":
		cond, err := p.parseAggregateCondition()
		if err != nil {
			return err
		}
		rule.Conditions = append(rule.Conditions, p.wrapOr(cond))
		return nil
	case "lower", "upper", "len":
		cond, err := p.parseTransformCondition()
		if err != nil {
			return err
		}
		rule.Conditions = append(rule.Conditions, p.wrapOr(cond))
		return nil
	default:
		// Must be a field comparison: resource.type == "x"
		cond, err := p.parseFieldCond()
		if err != nil {
			return err
		}
		rule.Conditions = append(rule.Conditions, p.wrapOr(cond))
		return nil
	}
}

// wrapOr checks if the next token is "or" and chains conditions into an OrGroup.
func (p *Parser) wrapOr(first types.Condition) types.Condition {
	if !p.checkIdent("or") {
		return first
	}

	group := []types.Condition{first}
	for p.checkIdent("or") {
		p.advance() // consume "or"
		cond, err := p.parseSingleCondition()
		if err != nil {
			// If we fail to parse after "or", return what we have.
			// The error will be caught on the next parseClause call.
			break
		}
		group = append(group, cond)
	}

	return types.Condition{
		Type:    types.CondOr,
		OrGroup: group,
	}
}

// parseSingleCondition parses one condition (without or-chaining).
func (p *Parser) parseSingleCondition() (types.Condition, error) {
	tok := p.peek()

	switch tok.Val {
	case "not":
		return p.parseNegatedCondition()
	case "any", "all":
		return p.parseQuantifier()
	case "has":
		return p.parseHasCondition()
	case "count":
		return p.parseAggregateCondition()
	case "lower", "upper", "len":
		return p.parseTransformCondition()
	default:
		return p.parseFieldCond()
	}
}

// parseNegatedCondition parses: not <condition>
func (p *Parser) parseNegatedCondition() (types.Condition, error) {
	p.advance() // consume "not"
	cond, err := p.parseSingleCondition()
	if err != nil {
		return types.Condition{}, err
	}
	cond.Negated = !cond.Negated
	return cond, nil
}

// parseHasCondition parses: has <field.path>
func (p *Parser) parseHasCondition() (types.Condition, error) {
	p.advance() // consume "has"
	field, err := p.parseDottedPath()
	if err != nil {
		return types.Condition{}, err
	}
	return types.Condition{
		Type:  types.CondHas,
		Field: field,
	}, nil
}

// parseQuantifier parses: any/all <list_field> <op> <value>
func (p *Parser) parseQuantifier() (types.Condition, error) {
	quantTok := p.advance() // consume "any" or "all"

	listField, err := p.parseDottedPath()
	if err != nil {
		return types.Condition{}, err
	}

	// Parse the predicate that will be applied to each element
	predicate, err := p.parseElementPredicate()
	if err != nil {
		return types.Condition{}, err
	}

	condType := types.CondAny
	if quantTok.Val == "all" {
		condType = types.CondAll
	}

	return types.Condition{
		Type:       condType,
		Quantifier: quantTok.Val,
		ListField:  listField,
		Predicate:  &predicate,
	}, nil
}

// parseElementPredicate parses the predicate part of an any/all condition.
// Supports: matches "pattern", in ["a", "b"], == "value", != "value", contains "value"
func (p *Parser) parseElementPredicate() (types.Condition, error) {
	tok := p.peek()

	// "in" followed by ["list"]
	if tok.Type == TokenIdent && tok.Val == "in" {
		p.advance() // consume "in"
		next := p.peek()
		if next.Type == TokenLBracket {
			vals, err := p.parseStringList()
			if err != nil {
				return types.Condition{}, err
			}
			return types.Condition{
				Type:  types.CondField,
				Op:    "in",
				Value: vals,
			}, nil
		}
		return types.Condition{}, p.errorf("expected list after 'in', got %s", next)
	}

	// "matches" or "matches_regex"
	if tok.Type == TokenIdent && (tok.Val == "matches" || tok.Val == "matches_regex") {
		op := tok.Val
		p.advance() // consume keyword
		valTok := p.advance()
		if valTok.Type != TokenString {
			return types.Condition{}, p.errorf("%s expects a string pattern, got %s", op, valTok)
		}
		return types.Condition{
			Type:  types.CondField,
			Op:    op,
			Value: valTok.Val,
		}, nil
	}

	// "contains"
	if tok.Type == TokenIdent && tok.Val == "contains" {
		p.advance() // consume "contains"
		val, err := p.parseValue()
		if err != nil {
			return types.Condition{}, err
		}
		return types.Condition{
			Type:  types.CondField,
			Op:    "contains",
			Value: val,
		}, nil
	}

	// Comparison operators
	opTok := p.advance()
	op := opTok.Val
	switch opTok.Type {
	case TokenEq, TokenNeq, TokenLt, TokenGt, TokenLte, TokenGte:
		// ok
	default:
		return types.Condition{}, p.errorf("expected operator in quantifier predicate, got %s", opTok)
	}

	val, err := p.parseValue()
	if err != nil {
		return types.Condition{}, err
	}

	return types.Condition{
		Type:  types.CondField,
		Op:    op,
		Value: val,
	}, nil
}

// parseFieldCond parses: field.path op value
// If arithmetic operators follow the field path, delegates to parseExprCondition.
func (p *Parser) parseFieldCond() (types.Condition, error) {
	field, err := p.parseDottedPath()
	if err != nil {
		return types.Condition{}, err
	}

	// Check if this is an arithmetic expression: field + ... op ...
	if p.isArithOp() {
		left := &types.Expr{Kind: types.ExprField, Field: field}
		return p.parseExprConditionFromLeft(left)
	}

	opTok := p.advance()
	op := opTok.Val

	switch opTok.Type {
	case TokenEq, TokenNeq, TokenLt, TokenGt, TokenLte, TokenGte:
		// ok
	default:
		if opTok.Type == TokenIdent && (opTok.Val == "in" || opTok.Val == "matches" || opTok.Val == "matches_regex" || opTok.Val == "contains" || opTok.Val == "intersects" || opTok.Val == "is_subset") {
			op = opTok.Val
		} else {
			return types.Condition{}, p.errorf("expected operator, got %s", opTok)
		}
	}

	cond := types.Condition{
		Type:  types.CondField,
		Field: field,
		Op:    op,
	}

	switch op {
	case "in", "intersects", "is_subset":
		vals, err := p.parseStringList()
		if err != nil {
			return types.Condition{}, err
		}
		cond.Value = vals
	case "matches", "matches_regex":
		valTok := p.advance()
		if valTok.Type != TokenString {
			return types.Condition{}, p.errorf("%s expects a string pattern, got %s", op, valTok)
		}
		cond.Value = valTok.Val
	default:
		val, err := p.parseValue()
		if err != nil {
			return types.Condition{}, err
		}
		cond.Value = val
	}

	return cond, nil
}

// isArithOp returns true if the next token is an arithmetic operator.
func (p *Parser) isArithOp() bool {
	tok := p.peek()
	return tok.Type == TokenPlus || tok.Type == TokenMinus || tok.Type == TokenStar || tok.Type == TokenSlash
}

// parseExprConditionFromLeft parses the rest of an arithmetic expression condition
// given an already-parsed left-hand term.
// Format: left (+|-|*|/ term)* comp_op right_expr
func (p *Parser) parseExprConditionFromLeft(left *types.Expr) (types.Condition, error) {
	expr, err := p.parseArithExprFrom(left)
	if err != nil {
		return types.Condition{}, err
	}

	// Parse comparison operator
	opTok := p.advance()
	switch opTok.Type {
	case TokenEq, TokenNeq, TokenLt, TokenGt, TokenLte, TokenGte:
		// ok
	default:
		return types.Condition{}, p.errorf("expected comparison operator in expression, got %s", opTok)
	}

	// Parse right-hand expression
	right, err := p.parseArithExpr()
	if err != nil {
		return types.Condition{}, err
	}

	return types.Condition{
		Type:      types.CondExpr,
		Op:        opTok.Val,
		LeftExpr:  expr,
		RightExpr: right,
	}, nil
}

// parseArithExpr parses a full arithmetic expression: term ((+|-|*|/) term)*
func (p *Parser) parseArithExpr() (*types.Expr, error) {
	left, err := p.parseExprTerm()
	if err != nil {
		return nil, err
	}
	return p.parseArithExprFrom(left)
}

// parseArithExprFrom continues parsing arithmetic from an existing left term.
func (p *Parser) parseArithExprFrom(left *types.Expr) (*types.Expr, error) {
	for p.isArithOp() {
		opTok := p.advance()
		right, err := p.parseExprTerm()
		if err != nil {
			return nil, err
		}
		left = &types.Expr{
			Kind:  types.ExprBinary,
			Op:    opTok.Val,
			Left:  left,
			Right: right,
		}
	}
	return left, nil
}

// parseExprTerm parses a single term: number | count(path) | len(path) | field.path
func (p *Parser) parseExprTerm() (*types.Expr, error) {
	tok := p.peek()

	// Numeric literal
	if tok.Type == TokenNumber {
		p.advance()
		n, err := strconv.ParseFloat(tok.Val, 64)
		if err != nil {
			return nil, p.errorf("invalid number: %s", tok.Val)
		}
		return &types.Expr{Kind: types.ExprLiteral, Value: n}, nil
	}

	// count(path) or len(path)
	if tok.Type == TokenIdent && (tok.Val == "count" || tok.Val == "len") {
		funcName := tok.Val
		p.advance() // consume function name
		if err := p.expect(TokenLParen); err != nil {
			return nil, err
		}
		path, err := p.parseDottedPath()
		if err != nil {
			return nil, err
		}
		if err := p.expect(TokenRParen); err != nil {
			return nil, err
		}
		if funcName == "count" {
			return &types.Expr{Kind: types.ExprCount, AggTarget: path}, nil
		}
		return &types.Expr{Kind: types.ExprLen, Field: path, Transform: "len"}, nil
	}

	// field.path
	if tok.Type == TokenIdent {
		path, err := p.parseDottedPath()
		if err != nil {
			return nil, err
		}
		return &types.Expr{Kind: types.ExprField, Field: path}, nil
	}

	return nil, p.errorf("expected number, field, count(), or len() in expression, got %s", tok)
}

// parseUnless parses: unless <condition>
func (p *Parser) parseUnless(rule *types.Rule) error {
	p.advance() // consume "unless"

	tok := p.peek()

	var cond types.Condition
	var err error

	switch tok.Val {
	case "not":
		cond, err = p.parseNegatedCondition()
	case "any", "all":
		cond, err = p.parseQuantifier()
	case "has":
		cond, err = p.parseHasCondition()
	case "lower", "upper", "len":
		cond, err = p.parseTransformCondition()
	case "count":
		cond, err = p.parseAggregateCondition()
	default:
		// Generic field condition as unless
		cond, err = p.parseFieldCond()
	}

	if err != nil {
		return err
	}

	rule.Unlesses = append(rule.Unlesses, cond)
	return nil
}

// parseTransformCondition parses: lower(field) op value, upper(field) op value, len(field) op value
func (p *Parser) parseTransformCondition() (types.Condition, error) {
	funcTok := p.advance() // consume "lower", "upper", or "len"
	if err := p.expect(TokenLParen); err != nil {
		return types.Condition{}, err
	}

	field, err := p.parseDottedPath()
	if err != nil {
		return types.Condition{}, err
	}

	if err := p.expect(TokenRParen); err != nil {
		return types.Condition{}, err
	}

	// For len(), if followed by arithmetic, switch to expression mode
	if funcTok.Val == "len" && p.isArithOp() {
		left := &types.Expr{Kind: types.ExprLen, Field: field, Transform: "len"}
		return p.parseExprConditionFromLeft(left)
	}

	opTok := p.advance()
	op := opTok.Val

	switch opTok.Type {
	case TokenEq, TokenNeq, TokenLt, TokenGt, TokenLte, TokenGte:
		// ok
	default:
		if opTok.Type == TokenIdent && (opTok.Val == "in" || opTok.Val == "matches" || opTok.Val == "matches_regex" || opTok.Val == "contains") {
			op = opTok.Val
		} else {
			return types.Condition{}, p.errorf("expected operator after %s(), got %s", funcTok.Val, opTok)
		}
	}

	cond := types.Condition{
		Type:      types.CondField,
		Field:     field,
		Op:        op,
		Transform: funcTok.Val,
	}

	switch op {
	case "in":
		vals, err := p.parseStringList()
		if err != nil {
			return types.Condition{}, err
		}
		cond.Value = vals
	case "matches", "matches_regex":
		valTok := p.advance()
		if valTok.Type != TokenString {
			return types.Condition{}, p.errorf("%s expects a string pattern, got %s", op, valTok)
		}
		cond.Value = valTok.Val
	default:
		val, err := p.parseValue()
		if err != nil {
			return types.Condition{}, err
		}
		cond.Value = val
	}

	return cond, nil
}

// parseAggregateCondition parses: count(plan.destroys) > 5
func (p *Parser) parseAggregateCondition() (types.Condition, error) {
	p.advance() // consume "count"
	if err := p.expect(TokenLParen); err != nil {
		return types.Condition{}, err
	}

	target, err := p.parseDottedPath()
	if err != nil {
		return types.Condition{}, err
	}

	if err := p.expect(TokenRParen); err != nil {
		return types.Condition{}, err
	}

	// If followed by arithmetic, switch to expression mode
	if p.isArithOp() {
		left := &types.Expr{Kind: types.ExprCount, AggTarget: target}
		return p.parseExprConditionFromLeft(left)
	}

	opTok := p.advance()
	if opTok.Type != TokenLt && opTok.Type != TokenGt && opTok.Type != TokenLte && opTok.Type != TokenGte && opTok.Type != TokenEq && opTok.Type != TokenNeq {
		return types.Condition{}, p.errorf("expected comparison operator after count(), got %s", opTok)
	}

	valTok := p.advance()
	if valTok.Type != TokenNumber {
		return types.Condition{}, p.errorf("expected number after operator, got %s", valTok)
	}

	num, err := strconv.Atoi(valTok.Val)
	if err != nil {
		return types.Condition{}, p.errorf("invalid number: %s", valTok.Val)
	}

	return types.Condition{
		Type:            types.CondAggregate,
		AggregateFunc:   "count",
		AggregateTarget: target,
		Op:              opTok.Val,
		Value:           num,
	}, nil
}

// parseMessage parses: message "template with {interpolation}"
func (p *Parser) parseMessage(rule *types.Rule) error {
	p.advance() // consume "message"
	msgTok := p.advance()
	if msgTok.Type != TokenString {
		return p.errorf("expected message string, got %s", msgTok)
	}
	rule.Message = msgTok.Val
	return nil
}

// parseMetadata parses: description|owner|link "value"
func (p *Parser) parseMetadata(rule *types.Rule, keyword string) error {
	p.advance() // consume keyword
	valTok := p.advance()
	if valTok.Type != TokenString {
		return p.errorf("expected string after %s, got %s", keyword, valTok)
	}
	switch keyword {
	case "description":
		rule.Description = valTok.Val
	case "owner":
		rule.Owner = valTok.Val
	case "link":
		rule.Link = valTok.Val
	}
	return nil
}

// --- Helpers ---

func (p *Parser) parseDottedPath() (string, error) {
	tok := p.advance()
	if tok.Type != TokenIdent {
		return "", p.errorf("expected identifier, got %s", tok)
	}
	path := tok.Val

	for p.check(TokenDot) {
		p.advance() // consume .
		next := p.advance()
		if next.Type != TokenIdent {
			return "", p.errorf("expected identifier after '.', got %s", next)
		}
		path += "." + next.Val
	}

	return path, nil
}

func (p *Parser) parseStringList() ([]string, error) {
	if err := p.expect(TokenLBracket); err != nil {
		return nil, err
	}

	var vals []string
	for !p.check(TokenRBracket) && !p.atEnd() {
		tok := p.advance()
		if tok.Type != TokenString {
			return nil, p.errorf("expected string in list, got %s", tok)
		}
		vals = append(vals, tok.Val)
		if p.check(TokenComma) {
			p.advance() // consume comma
		}
	}

	if err := p.expect(TokenRBracket); err != nil {
		return nil, err
	}

	return vals, nil
}

func (p *Parser) parseValue() (any, error) {
	tok := p.advance()
	switch tok.Type {
	case TokenString:
		return tok.Val, nil
	case TokenNumber:
		n, err := strconv.Atoi(tok.Val)
		if err != nil {
			// Try float
			f, err := strconv.ParseFloat(tok.Val, 64)
			if err != nil {
				return nil, p.errorf("invalid number: %s", tok.Val)
			}
			return f, nil
		}
		return n, nil
	case TokenIdent:
		switch tok.Val {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return nil, p.errorf("unexpected identifier %q in value position", tok.Val)
		}
	default:
		return nil, p.errorf("expected value, got %s", tok)
	}
}

func (p *Parser) peek() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *Parser) advance() Token {
	tok := p.peek()
	if tok.Type != TokenEOF {
		p.pos++
	}
	return tok
}

func (p *Parser) check(t TokenType) bool {
	return p.peek().Type == t
}

func (p *Parser) checkIdent(val string) bool {
	tok := p.peek()
	return tok.Type == TokenIdent && tok.Val == val
}

func (p *Parser) atEnd() bool {
	return p.peek().Type == TokenEOF
}

func (p *Parser) expect(t TokenType) error {
	tok := p.advance()
	if tok.Type != t {
		return p.errorf("expected %v, got %s", t, tok)
	}
	return nil
}

func (p *Parser) expectIdent(val string) error {
	tok := p.advance()
	if tok.Type != TokenIdent || tok.Val != val {
		return p.errorf("expected %q, got %s", val, tok)
	}
	return nil
}

func (p *Parser) errorf(format string, args ...any) error {
	tok := p.peek()
	prefix := fmt.Sprintf("line %d col %d: ", tok.Line, tok.Col)
	return fmt.Errorf(prefix+format, args...)
}
