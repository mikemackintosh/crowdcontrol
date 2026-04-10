/* Minimal Prism.js with a CrowdControl grammar
   Supports: crowdcontrol, bash, json, go
   This is a hand-rolled subset — no external dependency. */

(function () {
  const Prism = {
    languages: {},
    hooks: { all: {} },
    highlightAll() {
      document.querySelectorAll('code[class*="language-"]').forEach(code => {
        Prism.highlightElement(code);
      });
    },
    highlightElement(el) {
      const lang = [...el.classList]
        .find(c => c.startsWith('language-'))
        ?.replace('language-', '');
      if (!lang || !Prism.languages[lang]) return;
      const text = el.textContent;
      el.innerHTML = Prism.tokenize(text, Prism.languages[lang]);
    },
    tokenize(text, grammar) {
      let tokens = [{ text, matched: false }];
      for (const [name, rule] of Object.entries(grammar)) {
        const re = rule instanceof RegExp ? rule : rule.pattern;
        const alias = rule.alias || name;
        const newTokens = [];
        for (const tok of tokens) {
          if (tok.matched) { newTokens.push(tok); continue; }
          let last = 0;
          const str = tok.text;
          re.lastIndex = 0;
          let m;
          const flags = re.flags.includes('g') ? re.flags : re.flags + 'g';
          const gre = new RegExp(re.source, flags);
          while ((m = gre.exec(str)) !== null) {
            if (m.index > last) newTokens.push({ text: str.slice(last, m.index), matched: false });
            newTokens.push({ text: m[0], matched: true, alias });
            last = m.index + m[0].length;
            if (m[0].length === 0) gre.lastIndex++;
          }
          if (last < str.length) newTokens.push({ text: str.slice(last), matched: false });
        }
        tokens = newTokens;
      }
      return tokens.map(t => {
        const escaped = t.text
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;');
        if (!t.matched) return escaped;
        return `<span class="token ${t.alias}">${escaped}</span>`;
      }).join('');
    },
  };

  // crowdcontrol grammar — order matters, earlier rules win
  Prism.languages.crowdcontrol = {
    comment: /(?:#|\/\/).*/,
    string: /"(?:[^"\\]|\\.)*"/,
    'rule-kind': /\b(?:forbid|warn|permit)\b/,
    metadata: /\b(?:description|owner|link|message)\b/,
    boolean: /\b(?:true|false)\b/,
    'function': /\b(?:count|lower|upper|len)\b(?=\s*\()/,
    builtin: /\b(?:matches_regex|matches|contains|intersects|is_subset)\b/,
    keyword: /\b(?:unless|has|not|any|all|in|or)\b/,
    number: /\b\d+(?:\.\d+)?\b/,
    operator: /==|!=|<=|>=|<|>|\+|-|\*|\/|=/,
    punctuation: /[{}[\](),.]/,
  };
  Prism.languages.cc = Prism.languages.crowdcontrol;

  // bash grammar (minimal)
  Prism.languages.bash = {
    comment: /#.*/,
    string: /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/,
    keyword: /\b(?:if|then|else|fi|for|do|done|in|while|case|esac|function|return|export|cd|echo|mkdir|cat|cp|mv|rm)\b/,
    'function': /\b(?:go|cc|curl|git|brew|npm|pip|python|node|docker)\b/,
    number: /\b\d+\b/,
    operator: /\|\||&&|[|&;<>]/,
    variable: /\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^}]+\}/,
  };
  Prism.languages.shell = Prism.languages.bash;

  // json grammar
  Prism.languages.json = {
    comment: /\/\/.*/,
    property: /"(?:[^"\\]|\\.)*"(?=\s*:)/,
    string: /"(?:[^"\\]|\\.)*"/,
    number: /-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/,
    boolean: /\b(?:true|false)\b/,
    'null': { pattern: /\bnull\b/, alias: 'keyword' },
    punctuation: /[{}[\],:]/,
  };

  // go grammar (minimal)
  Prism.languages.go = {
    comment: /\/\/.*|\/\*[\s\S]*?\*\//,
    string: /"(?:[^"\\]|\\.)*"|`[^`]*`/,
    keyword: /\b(?:func|package|import|if|else|for|range|return|var|const|type|struct|interface|map|chan|go|defer|switch|case|default|break|continue|fallthrough|select|nil)\b/,
    'function': /\b[a-zA-Z_][a-zA-Z0-9_]*(?=\()/,
    boolean: /\b(?:true|false)\b/,
    number: /\b\d+(?:\.\d+)?\b/,
    operator: /:=|[+\-*/%&|^!<>=]=?|&&|\|\|/,
    punctuation: /[{}[\](),.;]/,
  };

  // yaml grammar (minimal, used in comparison docs)
  Prism.languages.yaml = {
    comment: /#.*/,
    property: /^\s*[a-zA-Z_][\w-]*(?=\s*:)/m,
    string: /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/,
    number: /\b\d+(?:\.\d+)?\b/,
    boolean: /\b(?:true|false|yes|no)\b/,
    punctuation: /[:\-,]/,
  };

  // rego grammar (minimal, for comparison page)
  Prism.languages.rego = {
    comment: /#.*/,
    string: /"(?:[^"\\]|\\.)*"/,
    keyword: /\b(?:package|import|default|not|with|as|some|every|in|if|else|contains|true|false|null)\b/,
    'function': /\b[a-z_][a-zA-Z0-9_]*(?=\()/,
    number: /\b\d+(?:\.\d+)?\b/,
    operator: /:=|==|!=|<=|>=|<|>|\+|-|\*|\/|=/,
    punctuation: /[{}[\](),.]/,
  };

  // cedar grammar (minimal)
  Prism.languages.cedar = {
    comment: /\/\/.*/,
    string: /"(?:[^"\\]|\\.)*"/,
    keyword: /\b(?:permit|forbid|when|unless|principal|action|resource|context|in|has|like|if|then|else|true|false)\b/,
    number: /\b\d+\b/,
    operator: /==|!=|<=|>=|<|>|&&|\|\|/,
    punctuation: /[{}[\](),.;:]/,
  };

  window.Prism = Prism;
})();
