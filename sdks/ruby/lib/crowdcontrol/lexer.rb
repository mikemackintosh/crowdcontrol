# frozen_string_literal: true

module CrowdControl
  # Raised when the lexer encounters invalid input.
  class LexError < StandardError; end

  # Token types — symbols are fine for a small, closed set.
  module TokenType
    EOF      = :eof
    IDENT    = :ident
    STRING   = :string
    NUMBER   = :number
    LBRACE   = :lbrace
    RBRACE   = :rbrace
    LBRACKET = :lbracket
    RBRACKET = :rbracket
    LPAREN   = :lparen
    RPAREN   = :rparen
    DOT      = :dot
    COMMA    = :comma
    EQ       = :eq
    NEQ      = :neq
    LT       = :lt
    GT       = :gt
    LTE      = :lte
    GTE      = :gte
    STAR     = :star
    PLUS     = :plus
    MINUS    = :minus
    SLASH    = :slash
  end

  # Token — a single lexed token.
  class Token
    attr_accessor :type, :val, :line, :col

    def initialize(type, val = "", line = 0, col = 0)
      @type = type
      @val  = val
      @line = line
      @col  = col
    end

    def to_s
      return "EOF" if @type == TokenType::EOF

      @val.inspect
    end
  end

  # Lexer — tokenizes CrowdControl source.
  class Lexer
    SINGLE_MAP = {
      "{" => TokenType::LBRACE,
      "}" => TokenType::RBRACE,
      "[" => TokenType::LBRACKET,
      "]" => TokenType::RBRACKET,
      "(" => TokenType::LPAREN,
      ")" => TokenType::RPAREN,
      "." => TokenType::DOT,
      "," => TokenType::COMMA,
      "<" => TokenType::LT,
      ">" => TokenType::GT,
      "*" => TokenType::STAR,
      "+" => TokenType::PLUS,
      "-" => TokenType::MINUS,
      "/" => TokenType::SLASH
    }.freeze

    TWO_CHAR_MAP = {
      "==" => TokenType::EQ,
      "!=" => TokenType::NEQ,
      "<=" => TokenType::LTE,
      ">=" => TokenType::GTE
    }.freeze

    def self.lex(source)
      new(source).run
    end

    def initialize(source)
      @input  = source
      @pos    = 0
      @line   = 1
      @col    = 1
      @tokens = []
    end

    def run
      n = @input.length
      while @pos < n
        ch = @input[@pos]

        # whitespace
        if whitespace?(ch)
          if ch == "\n"
            @line += 1
            @col = 1
          else
            @col += 1
          end
          @pos += 1
          next
        end

        # comments: # or //
        if ch == "#" || (ch == "/" && @pos + 1 < n && @input[@pos + 1] == "/")
          @pos += 1 while @pos < n && @input[@pos] != "\n"
          next
        end

        # string literal
        if ch == '"'
          @tokens << lex_string
          next
        end

        # number
        if digit?(ch)
          @tokens << lex_number
          next
        end

        # identifier / keyword
        if letter?(ch) || ch == "_"
          @tokens << lex_ident
          next
        end

        # two-character operators
        if @pos + 1 < n
          two = @input[@pos, 2]
          if (tt = TWO_CHAR_MAP[two])
            @tokens << Token.new(tt, two, @line, @col)
            @pos += 2
            @col += 2
            next
          end
        end

        # single-character tokens
        if (tt = SINGLE_MAP[ch])
          @tokens << Token.new(tt, ch, @line, @col)
          @pos += 1
          @col += 1
          next
        end

        raise LexError, "line #{@line} col #{@col}: unexpected character: #{ch}"
      end

      @tokens << Token.new(TokenType::EOF, "", @line, @col)
      @tokens
    end

    private

    def whitespace?(ch)
      ch == " " || ch == "\t" || ch == "\r" || ch == "\n"
    end

    def digit?(ch)
      ch && ch >= "0" && ch <= "9"
    end

    def letter?(ch)
      # Unicode letter-ish: use Ruby's regex match for safety.
      !ch.nil? && ch.match?(/\p{L}/)
    end

    def alnum?(ch)
      digit?(ch) || letter?(ch)
    end

    def lex_string
      start_col = @col
      @pos += 1
      @col += 1
      parts = String.new
      n = @input.length
      while @pos < n
        ch = @input[@pos]
        if ch == '"'
          @pos += 1
          @col += 1
          return Token.new(TokenType::STRING, parts, @line, start_col)
        end

        if ch == "\\" && @pos + 1 < n
          @pos += 1
          @col += 1
          nxt = @input[@pos]
          case nxt
          when '"', "\\"
            parts << nxt
          when "n"
            parts << "\n"
          when "t"
            parts << "\t"
          else
            parts << "\\"
            parts << nxt
          end
        else
          parts << ch
        end
        @pos += 1
        @col += 1
      end
      raise LexError, "line #{@line} col #{start_col}: unterminated string"
    end

    def lex_number
      start     = @pos
      start_col = @col
      n         = @input.length
      while @pos < n && (digit?(@input[@pos]) || @input[@pos] == ".")
        @pos += 1
        @col += 1
      end
      Token.new(TokenType::NUMBER, @input[start...@pos], @line, start_col)
    end

    def lex_ident
      start     = @pos
      start_col = @col
      n         = @input.length
      while @pos < n
        ch = @input[@pos]
        if alnum?(ch) || ch == "_"
          @pos += 1
          @col += 1
        else
          break
        end
      end
      Token.new(TokenType::IDENT, @input[start...@pos], @line, start_col)
    end
  end
end
