var __getOwnPropNames = Object.getOwnPropertyNames;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

// vendor/js-ast-validator/check-ast.js
var require_check_ast = __commonJS({
  "vendor/js-ast-validator/check-ast.js"(exports2, module2) {
    var pretty = require("jsonpretty");
    function string(value) {
      return typeof value === "string";
    }
    function number(value) {
      return typeof value === "number";
    }
    function boolean(value) {
      return typeof value === "boolean";
    }
    function regExp(value) {
      return value instanceof RegExp;
    }
    function isValue(value) {
      return function(item) {
        return item === value;
      };
    }
    function maybe(specItem) {
      var checkFunc2 = handler(specItem);
      var maubeCheck = function(node) {
        return node === null || node === void 0 || checkFunc2(node);
      };
      maubeCheck.toString = function() {
        return "maybe(" + stringify(specItem) + ")";
      };
      return maubeCheck;
    }
    function either() {
      var options = [];
      for (var i = 0; i < arguments.length; i++) {
        options.push(arguments[i]);
      }
      var handlers = options.map(handler);
      var checkFunc2 = function(node) {
        return handlers.some(function(checkFunc3) {
          return checkFunc3(node);
        });
      };
      checkFunc2.toString = function() {
        return handlers.map(stringify).join(" | ");
      };
      return checkFunc2;
    }
    function verify(node, spec) {
      if (node == null) {
        return false;
      }
      if (spec.type && spec.type !== node.type) {
        return false;
      }
      for (var key in spec) {
        if (!handler(spec[key])(node[key])) {
          var e = "Invalid value for property '" + key + "' in " + node.type + "\n    expected: " + stringify(spec[key]) + "\n    found: " + stringify(node[key]);
          throw Error(e);
        }
      }
      return true;
    }
    var handler = /* @__PURE__ */ function() {
      var typeHandlers = {
        string: function(str) {
          return function(value) {
            return value === str;
          };
        },
        object: function(obj) {
          if (obj instanceof Array) {
            return function(arr) {
              return arr instanceof Array && arr.every(handler(obj[0]));
            };
          }
          if (obj === null) {
            return isValue(null);
          }
          return function(node) {
            return verify(node, obj);
          };
        },
        function: function(func) {
          return func;
        },
        boolean: isValue
      };
      return function(value) {
        checkFunc = typeHandlers[typeof value];
        if (!checkFunc) {
          throw TypeError("Unknown type in specification");
        }
        return checkFunc(value);
      };
    }();
    function stringify(value) {
      switch (typeof value) {
        case "string":
          return '"' + value + '"';
        case "function":
          return value.name || value.toString();
        case "object":
          if (value === null) {
            return "null";
          }
          if (value instanceof Array) {
            return "[" + value.map(stringify) + "]";
          }
          return value.type || pretty(value);
        default:
          return "" + value;
      }
    }
    function always(value) {
      return function() {
        return value;
      };
    }
    function program(node) {
      return verify(node, {
        type: "Program",
        body: [statement]
      });
    }
    var statement = either(
      expressionStatement,
      variableDeclaration,
      functionDeclaration,
      blockStatement,
      ifStatement,
      returnStatement,
      switchStatement,
      throwStatement,
      tryStatement,
      whileStatement,
      doWhileStatement,
      forStatement,
      forInStatement,
      forOfStatement,
      breakStatement,
      continueStatement,
      emptyStatement,
      withStatement,
      debuggerStatement,
      labeledStatement
    );
    statement.toString = always("statement");
    function emptyStatement(node) {
      return verify(node, {
        type: "EmptyStatement"
      });
    }
    function blockStatement(node) {
      return verify(node, {
        type: "BlockStatement",
        body: [statement]
      });
    }
    function expressionStatement(node) {
      return verify(node, {
        type: "ExpressionStatement",
        expression
      });
    }
    function ifStatement(node) {
      return verify(node, {
        type: "IfStatement",
        test: expression,
        consequent: statement,
        alternate: maybe(statement)
      });
    }
    function labeledStatement(node) {
      return verify(node, {
        type: "LabeledStatement",
        label: identifier,
        body: statement
      });
    }
    function breakStatement(node) {
      return verify(node, {
        type: "BreakStatement",
        label: maybe(identifier)
      });
    }
    function continueStatement(node) {
      return verify(node, {
        type: "ContinueStatement",
        label: maybe(identifier)
      });
    }
    function withStatement(node) {
      return verify(node, {
        type: "WithStatement",
        object: expression,
        body: statement
      });
    }
    function switchStatement(node) {
      return verify(node, {
        type: "SwitchStatement",
        discriminant: expression,
        cases: [switchCase],
        lexical: maybe(boolean)
      });
    }
    function returnStatement(node) {
      return verify(node, {
        type: "ReturnStatement",
        argument: maybe(expression)
      });
    }
    function throwStatement(node) {
      return verify(node, {
        type: "ThrowStatement",
        argument: expression
      });
    }
    function tryStatement(node) {
      return verify(node, {
        type: "TryStatement",
        block: blockStatement,
        handler: maybe(catchClause),
        guardedHandlers: [catchClause],
        finalizer: maybe(blockStatement)
      });
    }
    function whileStatement(node) {
      return verify(node, {
        type: "WhileStatement",
        test: expression,
        body: statement
      });
    }
    function doWhileStatement(node) {
      return verify(node, {
        type: "DoWhileStatement",
        test: expression,
        body: statement
      });
    }
    function forStatement(node) {
      return verify(node, {
        type: "ForStatement",
        init: either(variableDeclaration, expression, null),
        test: maybe(expression),
        update: maybe(expression),
        body: statement
      });
    }
    function forInStatement(node) {
      return verify(node, {
        type: "ForInStatement",
        left: either(variableDeclaration, expression),
        right: expression,
        body: statement,
        each: boolean
      });
    }
    function forOfStatement(node) {
      return verify(node, {
        type: "ForOfStatement",
        left: either(variableDeclaration, expression),
        right: expression,
        body: statement
      });
    }
    function debuggerStatement(node) {
      return verify(node, {
        type: "DebuggerStatement"
      });
    }
    function functionDeclaration(node) {
      return verify(node, {
        type: "FunctionDeclaration",
        id: identifier,
        params: [pattern],
        defaults: [expression],
        body: blockStatement,
        rest: maybe(identifier),
        generator: boolean,
        expression: boolean
      });
    }
    function variableDeclaration(node) {
      return verify(node, {
        type: "VariableDeclaration",
        declarations: [variableDeclarator],
        kind: either("var", "let", "const")
      });
    }
    function variableDeclarator(node) {
      return verify(node, {
        type: "VariableDeclarator",
        id: pattern,
        init: maybe(expression)
      });
    }
    var expression = either(
      identifier,
      literal,
      callExpression,
      assignmentExpression,
      unaryExpression,
      binaryExpression,
      logicalExpression,
      arrayExpression,
      objectExpression,
      memberExpression,
      functionExpression,
      conditionalExpression,
      thisExpression,
      arrowExpression,
      sequenceExpression,
      updateExpression,
      newExpression,
      yieldExpression
    );
    expression.toString = always("expression");
    function thisExpression(node) {
      return verify(node, {
        type: "ThisExpression"
      });
    }
    function arrayExpression(node) {
      return verify(node, {
        type: "ArrayExpression",
        elements: [expression]
      });
    }
    function objectExpression(node) {
      return verify(node, {
        type: "ObjectExpression",
        properties: [{
          key: either(literal, identifier),
          value: expression,
          kind: either("init", "get", "set")
        }]
      });
    }
    function functionExpression(node) {
      return verify(node, {
        type: "FunctionExpression",
        id: maybe(identifier),
        params: [pattern],
        defaults: [expression],
        rest: maybe(identifier),
        body: either(blockStatement, expression),
        generator: boolean,
        expression: boolean
      });
    }
    function arrowExpression(node) {
      return verify(node, {
        type: "ArrowExpression",
        id: maybe(identifier),
        params: [pattern],
        defaults: [expression],
        rest: maybe(identifier),
        body: either(blockStatement, expression),
        generator: boolean,
        expression: boolean
      });
    }
    function sequenceExpression(node) {
      return verify(node, {
        type: "SequenceExpression",
        expressions: [expression]
      });
    }
    function unaryExpression(node) {
      return verify(node, {
        type: "UnaryExpression",
        operator: unaryOperator,
        prefix: boolean,
        argument: expression
      });
    }
    function binaryExpression(node) {
      return verify(node, {
        type: "BinaryExpression",
        operator: binaryOperator,
        left: expression,
        right: expression
      });
    }
    function assignmentExpression(node) {
      return verify(node, {
        type: "AssignmentExpression",
        operator: assignmentOperator,
        left: expression,
        right: expression
      });
    }
    function updateExpression(node) {
      return verify(node, {
        type: "UpdateExpression",
        operator: updateOperator,
        prefix: boolean,
        argument: expression
      });
    }
    function logicalExpression(node) {
      return verify(node, {
        type: "LogicalExpression",
        operator: logicalOperator,
        left: expression,
        right: expression
      });
    }
    function conditionalExpression(node) {
      return verify(node, {
        type: "ConditionalExpression",
        test: expression,
        consequent: expression,
        alternate: expression
      });
    }
    function newExpression(node) {
      return verify(node, {
        type: "NewExpression",
        callee: expression,
        arguments: [expression]
      });
    }
    function callExpression(node) {
      return verify(node, {
        type: "CallExpression",
        callee: expression,
        arguments: [expression]
      });
    }
    function memberExpression(node) {
      return verify(node, {
        type: "MemberExpression",
        object: expression,
        property: either(identifier, expression),
        computed: boolean
      });
    }
    function yieldExpression(node) {
      return verify(node, {
        type: "YieldExpression",
        argument: expression
      });
    }
    var pattern = either(identifier, objectPattern, arrayPattern);
    pattern.toString = always("pattern");
    function objectPattern(node) {
      return verify(node, {
        type: "ObjectPattern",
        properties: [{
          key: either(literal, identifier),
          value: pattern
        }]
      });
    }
    function arrayPattern(node) {
      return verify(node, {
        type: "ArrayPattern",
        elements: [maybe(pattern)]
      });
    }
    function identifier(node) {
      return verify(node, {
        type: "Identifier",
        name: string
      });
    }
    function switchCase(node) {
      return verify(node, {
        type: "SwitchCase",
        test: maybe(expression),
        consequent: either([statement], statement)
      });
    }
    function catchClause(node) {
      return verify(node, {
        type: "CatchClause",
        param: pattern,
        guard: maybe(expression),
        body: blockStatement
      });
    }
    function literal(node) {
      return verify(node, {
        type: "Literal",
        value: either(string, boolean, null, number, regExp)
      });
    }
    var unaryOperator = either("-", "+", "!", "~", "typeof", "void", "delete");
    var binaryOperator = either(
      "==",
      "!=",
      "===",
      "!==",
      "<",
      "<=",
      ">",
      ">=",
      "<<",
      ">>",
      ">>>",
      "+",
      "-",
      "*",
      "/",
      "%",
      "|",
      "^",
      "&",
      "in",
      "instanceof",
      ".."
    );
    var logicalOperator = either("||", "&&");
    var assignmentOperator = either(
      "=",
      "+=",
      "-=",
      "*=",
      "/=",
      "%=",
      "<<=",
      ">>=",
      ">>>=",
      "|=",
      "^=",
      "&="
    );
    var updateOperator = either("++", "--");
    module2.exports = function validateAST(node, nodeType) {
      nodeType = (nodeType || "program").toLowerCase();
      var nodeFunc = {
        program,
        expression,
        statement
      }[nodeType];
      if (!nodeFunc) {
        throw Error("Unknown node type. Must be one of 'expression', 'statement' or 'program'");
      }
      if (!nodeFunc(node)) {
        throw Error("Root node in AST is not a valid " + nodeType);
      }
      return true;
    };
  }
});

// lib/parse.js
var require_parse = __commonJS({
  "lib/parse.js"(exports2, module2) {
    "use strict";
    var esprima = require("esprima");
    var parseError = require("parse-error");
    var esprimaOpts = {
      sourceType: "module",
      ecmaVersion: 6,
      allowReturnOutsideFunction: true,
      allowHashBang: true,
      locations: true,
      attachComment: true
    };
    function ParseError(err, line, column, src, file) {
      SyntaxError.call(this);
      this.message = err.message.replace(/\s+\(\d+:\d+\)$/, "");
      this.line = line;
      this.column = column;
      this.stack = "\n" + (file || "(anonymous file)") + ":" + this.line + "\n" + src.split("\n")[this.line - 1] + "\n" + Array(this.column).join(" ") + "^\nParseError: " + this.message;
    }
    ParseError.prototype = Object.create(SyntaxError.prototype);
    ParseError.prototype.toString = function() {
      return this.annotated;
    };
    ParseError.prototype.inspect = function() {
      return this.annotated;
    };
    function indexToColumn(index, lineNumber, src) {
      if (lineNumber <= 1) {
        return index;
      }
      const linesBefore = src.split(/\n/g, lineNumber - 1).map((x) => x + "\n");
      const charactersBeforeThisLine = linesBefore.join("\n").length;
      return index - charactersBeforeThisLine;
    }
    module2.exports = function parse(js, filename) {
      try {
        return esprima.parse(js, esprimaOpts);
      } catch (e) {
        throw new ParseError(e, e.lineNumber, indexToColumn(e.index, e.lineNumber, js), js, filename);
      }
    };
  }
});

// lib/util/ast-builders.js
var require_ast_builders = __commonJS({
  "lib/util/ast-builders.js"(exports2, module2) {
    "use strict";
    var assert = require("assert");
    var { inspect } = require("util");
    var checkAST = require_check_ast();
    var esprima = require("esprima");
    var util = module2.exports;
    util.ensure = function ensure2(kind, value) {
      assert(value, "Didnt ensure value " + inspect(value));
      assert(value.type, "Value " + inspect(value) + " does not have a type property");
      assert(value.type in esprima.Syntax, "Value " + inspect(value) + " does not have a valid type");
      try {
        checkAST(value, kind);
      } catch (e) {
        e.message = `Invalid AST node in ${inspect(value)} ${e.message}`;
        throw e;
      }
      return value;
    };
    var ensure;
    util.enableTestMode = (enable = true) => {
      ensure = enable ? util.ensure : (_, x) => x;
    };
    util.enableTestMode(false);
    util.argumentsCache = () => esprima.parseScript(`[].slice.call(arguments,1);`).body[0].expression;
    util.functionExpression = ({
      body,
      bodyExpr,
      id,
      params = [],
      defaults = [],
      generator = false,
      expression = false
    }) => ensure("expression", {
      type: "FunctionExpression",
      id: id ? util.identifierIfString(id) : null,
      params: params.map(util.identifierIfString),
      defaults,
      generator,
      expression,
      body: body ? util.block(body) : bodyExpr ? util.block(util.return(bodyExpr)) : assert(false, "pass body or bodyExpr to util.function*")
    });
    util.functionDeclaration = (funExprArgs) => {
      const expr = util.functionExpression(funExprArgs);
      expr.type = "FunctionDeclaration";
      return ensure("statement", expr);
    };
    util.iifeWithArguments = (args, func) => {
      const params = Object.keys(args);
      const argumentValues = params.map((k) => args[k]);
      return util.iife(Object.assign({ params }, func), argumentValues);
    };
    util.iife = (func, args) => {
      if (!("body" in func) && !("bodyExpr" in func)) {
        return util.iife({ body: func }, args);
      }
      return ensure("expression", util.call(
        util.functionExpression(func),
        args
      ));
    };
    util.call = (callee, args = []) => ensure("expression", {
      type: "CallExpression",
      callee: util.identifierIfString(callee),
      arguments: args.map(util.identifierIfString)
    });
    util.new = (callee, args = []) => ensure("expression", {
      type: "NewExpression",
      callee: util.identifierIfString(callee),
      arguments: args
    });
    util.declaration = (name, init) => ensure("statement", {
      type: "VariableDeclaration",
      kind: "var",
      declarations: [
        { type: "VariableDeclarator", id: util.identifierIfString(name), init: util.identifierIfString(init) }
      ]
    });
    util.return = (argument) => ensure("statement", {
      type: "ReturnStatement",
      argument: util.identifierIfString(argument)
    });
    util.identifierIfString = (string) => {
      if (typeof string === "string") {
        return util.identifier(string);
      }
      if (string && string.type === "Identifier") {
        return util.identifier(string.name);
      }
      return string;
    };
    util.block = (body) => ensure("statement", { type: "BlockStatement", body: [].concat(body) });
    util.if = (test, consequent, alternate = null) => ensure("statement", {
      type: "IfStatement",
      test,
      consequent: util.block(consequent),
      alternate: alternate && util.block(alternate)
    });
    util.identifier = (name) => ensure("expression", { type: "Identifier", name });
    util.expressionStatement = (expression) => ensure("statement", {
      type: "ExpressionStatement",
      expression
    });
    util.assignment = (left, right) => ensure("expression", {
      type: "AssignmentExpression",
      operator: "=",
      left: util.identifierIfString(left),
      right: util.identifierIfString(right)
    });
    util.member = (object, property, computed = false) => ensure("expression", {
      type: "MemberExpression",
      computed,
      object: util.identifierIfString(object),
      property: util.identifierIfString(property)
    });
    util.property = (key, value, computed = false) => ({
      type: "Property",
      key: util.identifierIfString(key),
      value: util.identifierIfString(value),
      kind: "init",
      computed
    });
    util.object = (properties = {}) => ensure("expression", {
      type: "ObjectExpression",
      properties: Object.keys(properties).map((prop) => {
        return util.property(prop, properties[prop]);
      })
    });
    util.literal = (value) => ensure("expression", { type: "Literal", value });
    util.leadingBlockComment = (node, comments) => {
      node.leadingComments = node.leadingComments || [];
      node.leadingComments.push({
        type: "Block",
        value: comments
      });
      return node;
    };
  }
});

// lib/util/ast-classifiers.js
var require_ast_classifiers = __commonJS({
  "lib/util/ast-classifiers.js"(exports2, module2) {
    "use strict";
    var util = module2.exports;
    Object.assign(util, {
      isFunction: (node) => node && /^Function/.test(node.type),
      isBlockish: (node) => node && (/^(Switch|Block)Statement/.test(node.type) || node.type === "Program"),
      containsBlock: (node) => util.isFunction(node) || util.isBlockish(node),
      isVariableReference: (node, parent) => {
        if (node.type !== "Identifier") {
          return false;
        }
        if (util.isFunction(parent)) {
          return false;
        }
        if (parent.type === "MemberExpression") {
          return Boolean(
            // - identifier is the leftmost in the membex
            parent.object === node || // - identifier is in square brackets ( foo[x] )
            parent.computed && parent.property === node
          );
        }
        return true;
      }
    });
  }
});

// lib/util/index.js
var require_util = __commonJS({
  "lib/util/index.js"(exports2, module2) {
    "use strict";
    var assert = require("assert");
    var estraverse = require("estraverse");
    var escopeModule = require("escope");
    var flatten = require("lodash/flatten");
    var builders = require_ast_builders();
    var classifiers = require_ast_classifiers();
    var util = module2.exports;
    util.nameSluginator = function(prefix) {
      prefix = prefix || "_";
      function sluginator(name) {
        return prefix + name.replace(/./g, function(char) {
          if (!/[a-zA-Z0-9_]/.test(char)) return "";
          return char;
        });
      }
      var _nameCounter = 0;
      var _namesUsed = [];
      function generateName(name) {
        if (name) {
          var name = sluginator(name);
          if (_namesUsed.indexOf(name) === -1) {
            _namesUsed.push(name);
            return name;
          }
        }
        return "" + prefix + _nameCounter++;
      }
      return generateName;
    };
    util.escopeOfFunction = (scopeMan, node) => {
      const ret = scopeMan.acquire(node);
      if (ret.type === "function-expression-name") {
        return ret.childScopes[0];
      }
      return ret;
    };
    util.replaceStatements = (blockish, mapFn, { prepend } = {}) => {
      assert(util.isBlockish(blockish), "replaceStatements called with non-blockish");
      if (blockish.type == "BlockStatement") {
        return Object.assign(blockish, {
          body: flatten([prepend].concat(blockish.body.map(mapFn))).filter(Boolean)
        });
      }
      if (blockish.type == "Program") {
        return Object.assign(blockish, {
          body: flatten([prepend].concat(blockish.body.map(mapFn))).filter(Boolean)
        });
      }
      if (blockish.type == "SwitchStatement") {
        const ret = Object.assign(blockish, {
          cases: blockish.cases.map(
            (kase) => Object.assign(kase, {
              consequent: flatten(kase.consequent.map(mapFn)).filter(Boolean)
            })
          )
        });
        if (prepend) {
          return util.block(
            flatten([prepend].concat(ret)).filter(Boolean)
          );
        }
        return ret;
      }
      assert(false);
    };
    Object.keys(builders).forEach((k) => {
      Object.defineProperty(util, k, {
        get: () => builders[k]
      });
    });
    Object.keys(classifiers).forEach((k) => {
      Object.defineProperty(util, k, {
        get: () => classifiers[k]
      });
    });
  }
});

// lib/basic-transforms.js
var require_basic_transforms = __commonJS({
  "lib/basic-transforms.js"(exports2, module2) {
    "use strict";
    var assert = require("assert");
    var estraverse = require("estraverse");
    var util = require_util();
    module2.exports = (ast) => {
      const generateForInName = util.nameSluginator("_for_in_");
      ast = estraverse.replace(ast, {
        enter: (node) => {
          if (node.type === "ExpressionStatement") {
            if (node.expression.type === "Literal") {
              return estraverse.VisitorOption.Remove;
            }
            return node;
          } else if (node.type === "Literal") {
            return node;
          } else if (util.isBlockish(node)) {
            return util.replaceStatements(node, (node2) => extractDecls(node2, generateForInName));
          } else if (supportedNodeTypes.has(node.type)) {
            return node;
          } else {
            throw new Error("Unknown node type " + node.type + " in " + node);
          }
        }
      });
      return ast;
    };
    var extractDecls = (node, generateForInName) => {
      if (node.type === "VariableDeclaration" && node.declarations.length !== 1) {
        return multipleDeclarations(node.declarations, node.kind);
      }
      if (node.type === "ForInStatement") {
        return extractDeclarationFromForIn(node, generateForInName);
      }
      if (node.type === "ForStatement" && (node.init || {}).type === "VariableDeclaration") {
        const init = node.init;
        node.init = null;
        return multipleDeclarations(init.declarations, init.kind).concat([node]);
      }
      return node;
    };
    var multipleDeclarations = (decls, kind) => decls.map((decl) => ({
      type: "VariableDeclaration",
      declarations: [decl],
      kind
    }));
    var extractDeclarationFromForIn = (node, generateForInName) => {
      const wasDeclaration = node.left.type === "VariableDeclaration";
      const assignOrDecl = wasDeclaration ? util.declaration : util.assignment;
      const realName = wasDeclaration ? node.left.declarations[0].id.name : node.left.name;
      const shimName = generateForInName();
      node.left = util.declaration(shimName);
      node.body.body.unshift(assignOrDecl(realName, shimName));
      return node;
    };
    var supportedNodeTypes = [
      "Program",
      "Identifier",
      "CallExpression",
      "BlockStatement",
      "FunctionExpression",
      "FunctionDeclaration",
      "VariableDeclaration",
      "VariableDeclarator",
      "IfStatement",
      "UnaryExpression",
      "MemberExpression",
      "LogicalExpression",
      "BinaryExpression",
      "ContinueStatement",
      "TryStatement",
      "CatchClause",
      "ReturnStatement",
      "NewExpression",
      "ThrowStatement",
      "SequenceExpression",
      "AssignmentExpression",
      "ObjectExpression",
      "Property",
      "ConditionalExpression",
      "ForStatement",
      "ForInStatement",
      "UpdateExpression",
      "ArrayExpression",
      "ThisExpression",
      "SwitchStatement",
      "SwitchCase",
      "BreakStatement",
      "WhileStatement",
      "DoWhileStatement",
      "EmptyStatement"
    ].reduce((accum, item) => accum.add(item), /* @__PURE__ */ new Set());
  }
});

// lib/require-obliteratinator.js
var require_require_obliteratinator = __commonJS({
  "lib/require-obliteratinator.js"(exports2, module2) {
    "use strict";
    var assert = require("assert");
    var path = require("path");
    var fs = require("fs");
    var esprima = require("esprima");
    var estraverse = require("estraverse");
    var resolveSync = require("resolve").sync;
    var util = require_util();
    var coreModules = fs.readdirSync(__dirname + "/../node/lib").map((mod) => mod.replace(/\.js$/, ""));
    module2.exports = (ast, {
      readFileSync = fs.readFileSync,
      foundModules = {},
      filename = "",
      isMain = true,
      sluginator = null,
      _doWrap = true,
      resolve = resolveSync,
      slug,
      _recurse = module2.exports,
      transformRequiredModule
    } = {}) => {
      if (!sluginator) {
        sluginator = util.nameSluginator();
      }
      const dirname = path.dirname(filename);
      const justTheFilename = path.basename(filename);
      let otherModules = [];
      findModules(ast, resolve, dirname, (resolvedFilename) => {
        let slug2 = foundModules[resolvedFilename];
        if (!slug2) {
          slug2 = sluginator(path.basename(resolvedFilename).replace(/\.js$/, ""));
          let ast2 = esprima.parse(readFileSync(resolvedFilename) + "");
          if (transformRequiredModule) {
            ast2 = transformRequiredModule(ast2);
          }
          foundModules[resolvedFilename] = slug2;
          const thisModule = _recurse(ast2, {
            readFileSync,
            foundModules,
            filename: resolvedFilename,
            isMain: false,
            sluginator,
            _doWrap,
            _recurse,
            resolve,
            slug: slug2,
            transformRequiredModule
          });
          otherModules = otherModules.concat([thisModule.body]);
        }
        return "_require" + slug2;
      });
      if (_doWrap !== false && isMain === false) {
        if (!slug) slug = sluginator(justTheFilename.replace(/\.js$/i, ""));
        protectExportsAssignments(ast.body);
        ast.body = generateRequirerFunction({ slug, dirname, filename, body: ast.body });
        assert(typeof ast.body.length === "number");
      }
      ast.body = otherModules.reduce(
        (accum, bod) => accum.concat(bod),
        []
      ).concat(ast.body);
      return ast;
    };
    var findModules = (ast, resolve, dirname, getModuleSlug) => estraverse.replace(ast, {
      leave: (node) => {
        if (node.type === "CallExpression" && node.callee.name === "require" && node.arguments.length === 1 && node.arguments[0].type === "Literal") {
          const moduleName = node.arguments[0].value;
          let resolved;
          if (coreModules.indexOf(moduleName) != -1) {
            resolved = __dirname + `/../node/lib/${moduleName}.js`;
          } else {
            resolved = resolve(moduleName, { basedir: dirname });
          }
          const newName = getModuleSlug(resolved, node.arguments[0].value);
          if (newName) {
            return util.call(newName);
          }
        }
      }
    });
    var protectExportsAssignments = (body) => {
      body.forEach((statement) => {
        estraverse.traverse(statement, {
          enter: (node) => {
            if (node.type === "AssignmentExpression" && node.left.type === "MemberExpression" && node.left.object.name === "module" && node.left.property.name === "exports") {
              throw new Error("Assigning to module.exports is forbidden!");
            }
          }
        });
      });
    };
    var wrapModuleContents = ({ body, filename = "", dirname = "", slug }) => [
      util.declaration("module", util.object({
        exports: "_module" + slug
      })),
      util.declaration("exports", "_module" + slug),
      util.declaration("__filename", util.literal(filename)),
      util.declaration("__dirname", util.literal(dirname)),
      ...body,
      util.return("_module" + slug)
    ];
    var generateRequirerFunction = ({ slug, dirname, filename, body }) => [
      util.declaration("_was_module_initialised" + slug, util.literal(false)),
      util.declaration("_module" + slug, util.object()),
      util.functionDeclaration({
        id: "_initmodule" + slug,
        body: wrapModuleContents({ slug, body, filename, dirname })
      }),
      util.functionDeclaration({
        id: "_require" + slug,
        body: [
          util.if(
            util.identifier("_was_module_initialised" + slug),
            util.return("_module" + slug)
          ),
          util.expressionStatement(
            util.assignment(
              "_module" + slug,
              util.call("_initmodule" + slug)
            )
          ),
          util.return("_module" + slug)
        ]
      })
    ];
  }
});

// lib/type-conversions.js
var require_type_conversions = __commonJS({
  "lib/type-conversions.js"(exports2, module2) {
    "use strict";
    var assert = require("assert");
    var tern = require("tern/lib/infer");
    var estraverse = require("estraverse");
    var util = require_util();
    module2.exports = function binOps(ast, options) {
      options = options || {};
      tern.withContext(new tern.Context(), function() {
        tern.analyze(ast);
        _binOps(ast, tern.cx().topScope, options);
      });
    };
    function _binOps(ast, ternState, options) {
      var ternContext = tern.cx();
      estraverse.replace(ast, {
        enter: function(node) {
          if (node !== ast && /^Function/.test(node.type)) {
            _binOps(node, node.scope, options);
            return this.skip();
          }
          if (node.type === "BinaryExpression") {
            var leftType = tern.expressionType({ node: node.left, state: ternState });
            var rightType = tern.expressionType({ node: node.right, state: ternState });
            if (leftType && leftType !== tern.ANull) {
              leftType = leftType.getType(false);
            }
            if (leftType && rightType !== tern.ANull) {
              rightType = rightType.getType(false);
            }
            if (!leftType || !rightType) {
              return;
            }
            if (leftType instanceof tern.Prim && rightType instanceof tern.Prim && leftType.name === rightType.name) {
              return;
            }
            if (node.operator === "+" && (leftType === tern.ANull || rightType === tern.ANull) && options.avoidJSAdd !== true) {
              return util.call("JS_ADD", [node.left, node.right]);
            }
            if (node.operator === "+" && (convertsToStringWhenAdding(leftType) || convertsToStringWhenAdding(rightType))) {
              if (leftType.name !== "string") {
                node.left = util.call("String", [node.left]);
              }
              if (rightType.name !== "string") {
                node.right = util.call("String", [node.right]);
              }
              return node;
            } else {
              return {
                type: "BinaryExpression",
                operator: node.operator,
                left: leftType.name !== "number" ? util.call("Number", [node.left]) : node.left,
                right: rightType.name !== "number" ? util.call("Number", [node.right]) : node.right
              };
            }
          }
          if (node.type === "UnaryExpression") {
            if (node.operator === "-") {
              return {
                type: "UnaryExpression",
                operator: node.operator,
                argument: util.call("Number", [node.argument]),
                prefix: node.prefix
              };
            }
            if (node.operator === "+") {
              return util.call("Number", [node.argument]);
            }
          }
        }
      });
    }
    function convertsToStringWhenAdding(type) {
      return type.name === "string" || type instanceof tern.Fn || type instanceof tern.Obj || type instanceof tern.Arr;
    }
  }
});

// lib/topmost.coffee
var require_topmost = __commonJS({
  "lib/topmost.coffee"(exports2, module2) {
    (function() {
      var assert, escope, estraverse, findNiceFunctionName, nameSluginator, specificAssignee, util;
      assert = require("assert");
      escope = require("escope");
      estraverse = require("estraverse");
      util = require_util();
      nameSluginator = util.nameSluginator;
      specificAssignee = function(assignment) {
        if (assignment.type === "Identifier") {
          return assignment.name;
        } else if (assignment.left.type === "Identifier") {
          return assignment.left.name;
        } else if (assignment.left.type === "MemberExpression") {
          return specificAssignee(assignment.left.property);
        } else {
          return "";
        }
      };
      findNiceFunctionName = function(func, parent) {
        if (func.id) {
          return func.id.name;
        } else if ((parent != null ? parent.type : void 0) === "AssignmentExpression") {
          return specificAssignee(parent);
        } else {
          return "";
        }
      };
      module2.exports = function(programNode) {
        var changeNames, currentIdx, currentScope, generateName, insertFuncs, insertVars, scopeMan, scopeStack;
        assert(typeof programNode.body.length === "number");
        insertFuncs = [];
        insertVars = [];
        changeNames = [];
        currentIdx = 0;
        scopeMan = escope.analyze(programNode);
        scopeStack = [scopeMan.acquire(programNode)];
        currentScope = function() {
          return scopeStack[scopeStack.length - 1];
        };
        generateName = nameSluginator("_flatten_");
        estraverse.traverse(programNode, {
          enter: function(node) {
            var scope;
            if (util.isFunction(node)) {
              scope = scopeMan.acquire(node);
              if (scope.type === "function-expression-name") {
                scope = scope.childScopes[0];
              }
              return scopeStack.push(scope);
            }
          },
          leave: function(node, parent) {
            var functionName, i, j, len, len1, newName, ref, ref1, ref2, results, scopeInsideFunction, variable;
            if (util.isFunction(node)) {
              scopeStack.pop();
            }
            if (parent && parent.type === "Program") {
              currentIdx = parent.body.indexOf(node);
              assert(currentIdx > -1);
            }
            if ((parent && parent.type) !== "Program") {
              if (node.type === "FunctionDeclaration") {
                newName = generateName(node.id && node.id.name);
                changeNames.push({
                  id: node.id,
                  name: newName
                });
                ref1 = currentScope().references;
                for (i = 0, len = ref1.length; i < len; i++) {
                  ref = ref1[i];
                  if (ref.identifier.name === node.id.name) {
                    changeNames.push({
                      id: ref.identifier,
                      name: newName
                    });
                  }
                }
                insertFuncs.push({
                  insert: node,
                  into: currentIdx
                });
              }
              if (node.type === "FunctionExpression") {
                variable = generateName(findNiceFunctionName(node, parent));
                insertVars.push({
                  insert: node,
                  into: currentIdx,
                  variable
                });
              }
              if (util.isFunction(node) && node.id) {
                functionName = node.id;
                scopeInsideFunction = scopeMan.acquire(node);
                ref2 = scopeInsideFunction.references;
                results = [];
                for (j = 0, len1 = ref2.length; j < len1; j++) {
                  ref = ref2[j];
                  if (ref.resolved && ref.resolved.defs[0] && ref.resolved.defs[0].type === "FunctionName" && ref.resolved.defs[0].node.id === functionName) {
                    results.push(changeNames.push({
                      id: ref.identifier,
                      name: newName
                    }));
                  } else {
                    results.push(void 0);
                  }
                }
                return results;
              }
            }
          }
        });
        estraverse.replace(programNode, {
          leave: function(node, parent) {
            var i, insert, j, len, len1, variable;
            for (i = 0, len = insertFuncs.length; i < len; i++) {
              ({ insert } = insertFuncs[i]);
              if (node === insert) {
                return this.remove();
              }
            }
            for (j = 0, len1 = insertVars.length; j < len1; j++) {
              ({ insert, variable } = insertVars[j]);
              if (node === insert) {
                return util.identifier(variable);
              }
            }
            return node;
          }
        });
        changeNames.forEach(function(toChange) {
          return toChange.id.name = toChange.name;
        });
        insertFuncs.forEach(function(toInsert) {
          return programNode.body.splice(toInsert.into, 0, toInsert.insert);
        });
        return insertVars.forEach(function(toInsert) {
          return programNode.body.splice(toInsert.into, 0, util.declaration(toInsert.variable, toInsert.insert));
        });
      };
    }).call(exports2);
  }
});

// lib/declosurify.coffee
var require_declosurify = __commonJS({
  "lib/declosurify.coffee"(exports2, module2) {
    (function() {
      var _declosurify, assert, assignment, escope, estraverse, flatten, function_needs_closure, is_above, tern, util, indexOf = [].indexOf;
      assert = require("assert");
      escope = require("escope");
      estraverse = require("estraverse");
      flatten = require("lodash/flatten");
      tern = require("tern/lib/infer");
      util = require_util();
      module2.exports = function() {
        var args;
        args = [].slice.call(arguments);
        return tern.withContext(new tern.Context(), function() {
          return _declosurify.apply(null, args);
        });
      };
      _declosurify = function(programNode, opt = {}) {
        var all_functions_below, closure, closureName, closure_name, current_function, current_scope, escope_scope, escope_scope_stack, func, functions_declared, getTernScopePath, ident_refers_to_a_function, ident_to_member_expr, j, k, len, len1, otherClosures, ref1, results, scopeMan, scope_below_using, scope_has_name, scope_of_function, scope_stack, scope_with, should_turn_ident_into_member_expression, ternScopePath, this_function_passes_closure, this_function_takes_closure, to_unshift, upperClosure, upper_scope;
        scopeMan = escope.analyze(programNode);
        tern.analyze(programNode);
        scope_stack = [];
        escope_scope_stack = [scopeMan.acquire(programNode)];
        escope_scope = function() {
          return escope_scope_stack[escope_scope_stack.length - 1];
        };
        current_scope = function() {
          return scope_stack[scope_stack.length - 1];
        };
        upper_scope = function() {
          return scope_stack[scope_stack.length - 2];
        };
        closure_name = util.nameSluginator("_closure_");
        scope_of_function = function(node) {
          var scope;
          scope = scopeMan.acquire(node);
          if (scope.type === "function-expression-name") {
            scope = scope.childScopes[0];
          }
          return scope;
        };
        scope_with = function(name) {
          var i;
          assert(typeof name === "string");
          i = scope_stack.length;
          while (i--) {
            if (scope_has_name(scope_stack[i], name)) {
              return scope_stack[i];
            }
          }
        };
        scope_has_name = function(scope, name) {
          return !!(scope.props[name] || indexOf.call(scope.fnType.argNames, name) >= 0 || indexOf.call(functions_declared(scope.originNode), name) >= 0);
        };
        scope_below_using = function(scope, name, _is_first = true) {
          var was_declared, was_used;
          if (!_is_first) {
            was_declared = scope.variables.some(function(variable) {
              return variable.name === name;
            });
            if (was_declared) {
              return false;
            }
            was_used = scope.references.some(function(ref) {
              return ref.identifier.name === name;
            });
            if (was_used) {
              return true;
            }
          }
          return scope.childScopes.some(function(s) {
            return scope_below_using(s, name, false);
          });
        };
        functions_declared = function(functionNode, { nodes } = {}) {
          var funcs;
          if (opt.funcs === false) {
            return [];
          }
          funcs = [];
          estraverse.traverse(functionNode, {
            enter: function(node) {
              var decl, name_to_push, node_to_push;
              if (node === functionNode) {
                return;
              }
              node_to_push = null;
              name_to_push = null;
              if (node.type === "FunctionDeclaration" && node.id) {
                node_to_push = node;
                name_to_push = node.id.name;
              }
              if (node.type === "VariableDeclaration") {
                decl = node.declarations[0];
                if (util.isFunction(decl.init)) {
                  node_to_push = decl.init;
                  if (decl.id.type === "MemberExpression") {
                    name_to_push = decl.id.property.name;
                  } else {
                    name_to_push = decl.id.name;
                  }
                }
              }
              if (node_to_push) {
                if (nodes) {
                  funcs.push([node_to_push, name_to_push]);
                } else {
                  funcs.push(name_to_push);
                }
              }
              if (util.isFunction(node)) {
                return this.skip();
              }
            }
          });
          return funcs;
        };
        current_function = function() {
          return scope_stack[scope_stack.length - 1].originNode;
        };
        getTernScopePath = function(_from) {
          var ref12, tern_scope, uses_upper_closure;
          _from = _from || 2;
          tern_scope = scope_stack[scope_stack.length - _from];
          uses_upper_closure = tern_scope && ((ref12 = tern_scope.originNode.params[0]) != null ? ref12.name : void 0) === "_closure";
          if (uses_upper_closure) {
            return [tern_scope].concat(getTernScopePath(_from + 1));
          }
          if (tern_scope) {
            return [tern_scope];
          }
          return [];
        };
        to_unshift = [];
        all_functions_below = function(func2) {
          var funcs;
          funcs = [];
          estraverse.traverse(func2, {
            enter: function(node) {
              if (node === func2) {
                return;
              }
              if (util.isFunction(node)) {
                return funcs.push(node);
              }
            }
          });
          return funcs;
        };
        this_function_passes_closure = function() {
          var funcs_below, j2, len2, ref12, throughs, variable;
          if (opt.always_create_closures) {
            return true;
          }
          ref12 = escope_scope().variables;
          for (j2 = 0, len2 = ref12.length; j2 < len2; j2++) {
            variable = ref12[j2];
            if (variable.stack === false) {
              return true;
            }
          }
          if (util.isFunction(escope_scope().block)) {
            funcs_below = all_functions_below(escope_scope().block);
            if (funcs_below.length) {
              throughs = escope_scope().through.map(function(through) {
                return through.resolved;
              });
              return funcs_below.map(function(node) {
                return scope_of_function(node);
              }).some(function(scope) {
                return scope.through.some(function(through) {
                  var ref2;
                  return through.resolved !== null && (ref2 = through.resolved, indexOf.call(throughs, ref2) >= 0);
                });
              });
            }
          }
          return false;
        };
        this_function_takes_closure = function() {
          var j2, k2, len2, len12, ref, ref12, ref2, through;
          if (opt.always_create_closures) {
            return true;
          }
          ref12 = escope_scope().references;
          for (j2 = 0, len2 = ref12.length; j2 < len2; j2++) {
            ref = ref12[j2];
            if (ref.resolved && ref.resolved.stack !== true && is_above(ref.resolved.scope, escope_scope())) {
              return true;
            }
          }
          ref2 = escope_scope().through;
          for (k2 = 0, len12 = ref2.length; k2 < len12; k2++) {
            through = ref2[k2];
            if (through.resolved) {
              return true;
            }
          }
          return false;
        };
        ident_refers_to_a_function = function(ident) {
          var def, ref;
          ref = escope_scope().resolve(ident);
          if (ref != null ? ref.resolved : void 0) {
            def = ref.resolved.defs.find(function(def2) {
              return def2.type === "FunctionName";
            });
            if (def) {
              return true;
            }
          }
        };
        ident_to_member_expr = function(node) {
          var identScope, lookInClosuresArgument;
          identScope = scope_with(node.name);
          if (identScope) {
            lookInClosuresArgument = opt.recursiveClosures !== false && current_scope() !== identScope;
            if (lookInClosuresArgument && upper_scope() === identScope) {
              return util.member("_closure", node.name);
            } else if (lookInClosuresArgument && upper_scope() !== identScope) {
              return util.member(util.member("_closure", identScope.name), node.name);
            } else if (identScope.name) {
              return util.member(identScope.name, node.name);
            }
          }
        };
        should_turn_ident_into_member_expression = function(ident, parent) {
          var is_for_in_variable, is_func_ref, is_ref, shared_with_lower_scope;
          is_ref = current_scope() && util.isVariableReference(ident, parent);
          if (!is_ref) {
            return false;
          }
          is_for_in_variable = ident.name.startsWith("_for_in_");
          if (is_for_in_variable) {
            return false;
          }
          shared_with_lower_scope = this_function_passes_closure() && scope_below_using(escope_scope(), ident.name);
          is_func_ref = ident_refers_to_a_function(ident) && parent.id !== ident;
          return this_function_takes_closure() || shared_with_lower_scope || is_func_ref;
        };
        estraverse.replace(programNode, {
          enter: function(node, parent) {
            if (util.isFunction(node)) {
              escope_scope_stack.push(scope_of_function(node));
              scope_stack.push(node.scope);
              assert(node.scope);
              if (this_function_passes_closure()) {
                node.scope.name = closure_name();
                to_unshift.push({
                  func: node,
                  closureName: node.scope.name,
                  ternScopePath: getTernScopePath()
                });
              }
              if (this_function_takes_closure()) {
                if (parent !== programNode && opt.recursiveClosures !== false) {
                  node.params.unshift(util.identifier("_closure"));
                }
              }
            }
            return node;
          },
          leave: function(node, parent) {
            var assign_or_declare, bod, extract_var_decls, funct, j2, k2, len2, len12, name, param, ref12, ref2, ref3, ref4;
            if (util.isFunction(node)) {
              node.stmts.unhift(util.declaration("$arguments_cache", util.argumentsCache()));
              escope_scope_stack.pop();
              scope_stack.pop();
              return;
            }
            if (this_function_takes_closure()) {
              if ((ref12 = node.type) === "Identifier" && node.name === "arguments") {
                node.name = "$arguments_cache";
                return node;
              }
            }
            if ((ref2 = node.type) === "Identifier" && should_turn_ident_into_member_expression(node, parent)) {
              return ident_to_member_expr(node);
            }
            if (util.isBlockish(node) && this_function_passes_closure()) {
              bod = [];
              if (util.isFunction(parent)) {
                if (opt.params !== false) {
                  ref3 = parent.params;
                  for (j2 = 0, len2 = ref3.length; j2 < len2; j2++) {
                    param = ref3[j2];
                    if (scope_below_using(escope_scope(), param.name)) {
                      if (param.name !== "_closure") {
                        bod.push(assignment(util.member(scope_with(param.name).name, param.name), param));
                      }
                    }
                  }
                }
                if (opt.fname !== false) {
                  ref4 = functions_declared(parent, {
                    nodes: true
                  });
                  for (k2 = 0, len12 = ref4.length; k2 < len12; k2++) {
                    [funct, name] = ref4[k2];
                    bod.push(assignment(util.member(current_scope().name, name), name));
                  }
                }
              }
              assign_or_declare = function(id, init = "undefined") {
                if (id.type === "MemberExpression") {
                  return assignment(id, init);
                } else {
                  assert.equal(id.type, "Identifier");
                  return util.declaration(id.name, init);
                }
              };
              extract_var_decls = function(_node) {
                var decl, declosurified, fName, ref5;
                if (_node.type === "VariableDeclaration") {
                  declosurified = [];
                  decl = _node.declarations[0];
                  if (((ref5 = decl.init) != null ? ref5.type : void 0) !== "FunctionExpression") {
                    return assign_or_declare(decl.id, decl.init);
                  } else if (decl.init) {
                    if (decl.id.type === "MemberExpression") {
                      fName = decl.id.property.name;
                    } else {
                      fName = decl.id.name;
                    }
                    decl.init.type = "FunctionDeclaration";
                    decl.init.id = util.identifier(fName);
                    return decl.init;
                  }
                }
                return _node;
              };
              return util.replaceStatements(node, extract_var_decls, {
                prepend: bod
              });
            }
            return node;
          }
        });
        results = [];
        for (j = 0, len = to_unshift.length; j < len; j++) {
          ({ func, closureName, ternScopePath } = to_unshift[j]);
          if (opt.recursiveClosures !== false && ternScopePath.length !== 0 && ((ref1 = func.params[0]) != null ? ref1.name : void 0) === "_closure") {
            [upperClosure, ...otherClosures] = ternScopePath;
            otherClosures.reverse();
            for (k = 0, len1 = otherClosures.length; k < len1; k++) {
              closure = otherClosures[k];
              if (closure.name) {
                func.body.body.unshift(assignment(util.member(closureName, closure.name), util.member("_closure", closure.name)));
              }
            }
            if (upperClosure.name) {
              func.body.body.unshift(assignment(util.member(closureName, upperClosure.name), "_closure"));
            }
          }
          results.push(func.body.body.unshift(util.declaration(closureName, util.object())));
        }
        return results;
      };
      assignment = function(...args) {
        return util.expressionStatement(util.assignment(...args));
      };
      function_needs_closure = function(funct) {
        return Boolean(funct.params.find(function(parm) {
          return parm.name === "_closure";
        }));
      };
      is_above = function(above, scope) {
        assert(scope, "scope is " + scope);
        assert(above, "above is " + above);
        assert(scope.upper !== void 0, "scope is not a scope, its .upper is " + scope.upper);
        assert(above.upper !== void 0, "above is not a scope, its .upper is " + above.upper);
        while (scope) {
          scope = scope.upper;
          if (scope === above) {
            return true;
          }
        }
        return false;
      };
    }).call(exports2);
  }
});

// lib/bindify.js
var require_bindify = __commonJS({
  "lib/bindify.js"(exports2, module2) {
    "use strict";
    var assert = require("assert");
    var escope = require("escope");
    var estraverse = require("estraverse");
    var util = require_util();
    module2.exports = function(programNode, options) {
      var bindFunctionName = options && options.bindFunctionName || "BIND";
      var toWrap = /* @__PURE__ */ new Map();
      var scopeMan = escope.analyze(programNode);
      var scopeStack = [scopeMan.acquire(programNode)];
      var currentScope = function() {
        return scopeStack[scopeStack.length - 1];
      };
      estraverse.traverse(programNode, {
        enter: function(node, parent) {
          if (util.isFunction(node)) {
            var scope = scopeMan.acquire(node);
            if (scope.type === "function-expression-name") {
              scope = scope.childScopes[0];
            }
            scopeStack.push(scope);
            return;
          }
          if (node.type === "Identifier" && /^_flatten_/.test(node.name) && !util.isFunction(parent) && !(parent.type === "VariableDeclarator" && parent.id === node)) {
            var closure = currentScope().variables.filter(function(p) {
              return /^_closure_/.test(p.name);
            })[0];
            if (closure && funcNeedsBind(programNode, node.name)) {
              toWrap.set(node, closure.name);
            }
          }
        },
        leave: function(node) {
          if (util.isFunction(node)) {
            scopeStack.pop();
          }
        }
      });
      estraverse.replace(programNode, {
        leave: function(node, parent) {
          if (node.type === "Identifier" && toWrap.has(node) && !(parent.type === "CallExpression" && parent.callee === node)) {
            var closureName = toWrap.get(node);
            if (closureName) {
              return util.call(bindFunctionName, [node, util.identifier(closureName)]);
            }
          }
          if (node.type === "CallExpression" && toWrap.has(node.callee)) {
            var closureName = toWrap.get(node.callee);
            return util.call(node.callee.name, [util.identifier(closureName), ...node.arguments]);
          }
        }
      });
    };
    module2.exports.name = function(options) {
      var bindFunctionName = options && options.bindFunctionName || "BIND";
      return bindFunctionName;
    };
    function funcNeedsBind(program, funcName) {
      var firstParam = funcByName(program, funcName).params[0];
      return firstParam && firstParam.name === "_closure";
    }
    function funcByName(program, needle) {
      return allFuncs(program.body).filter(function(nodeAndName) {
        return nodeAndName.name === needle;
      })[0].node;
    }
    function allFuncs(body) {
      return body.map(getFuncDecl).filter((decl) => decl != null);
    }
    function getFuncDecl(node) {
      if (util.isFunction(node)) {
        return { node, name: node.id.name };
      }
      if (node.type === "VariableDeclaration" && util.isFunction(node.declarations[0].init)) {
        return { node: node.declarations[0].init, name: node.declarations[0].id.name };
      }
      return void 0;
    }
  }
});

// lib/mainify.js
var require_mainify = __commonJS({
  "lib/mainify.js"(exports2, module2) {
    "use strict";
    var util = require_util();
    module2.exports = function(ast, { prepend = [], append = [] } = {}) {
      ast.body = [
        util.functionDeclaration({
          id: "main",
          body: [...prepend, ...ast.body, ...append]
        })
      ];
      return ast;
    };
  }
});

// lib/thatter.js
var require_thatter = __commonJS({
  "lib/thatter.js"(exports2, module2) {
    "use strict";
    var tern = require("tern/lib/infer");
    var estraverse = require("estraverse");
    var assert = require("assert");
    var util = require_util();
    module2.exports = function(ast) {
      var toReplace = thatter(ast);
      replaceCalls(ast, toReplace);
    };
    function thatter(ast) {
      var usesThis = false;
      var out = [];
      estraverse.replace(ast, {
        enter: function(node) {
          if (node === ast) {
            return;
          }
          if (/^Function/.test(node.type)) {
            out = out.concat(thatter(node));
            return this.skip();
          }
          if (node.type === "ThisExpression" && ast.type !== "Program") {
            usesThis = true;
            return util.identifier("_self");
          }
        }
      });
      estraverse.replace(ast, {
        enter: function(node) {
          if (node.type === "Identifier" && node.name === "arguments") return util.identifier("$arguments_cache2");
        }
      });
      ast.params.unshift(util.identifier("_self"));
      ast.stmts.unshift(util.declaration("$arguments_cache2", util.argumentsCache()));
      var functionNode = ast;
      out = out.concat([functionNode]);
      return out;
    }
    function replaceCalls(ast, toReplace) {
      var cx = new tern.Context();
      tern.withContext(cx, function() {
        tern.analyze(ast, "-", cx.topScope);
        var scope = cx.topScope;
        estraverse.replace(ast, {
          enter: function(node) {
            if (node === ast) {
              return;
            }
            if (/^Function/.test(node.type)) {
              scope = node.scope;
            }
          },
          leave: function(node) {
            if (/^Function/.test(node.type)) {
              scope = node.scope;
            }
            if (node.type === "CallExpression" && node.callee.type === "MemberExpression" && node.callee.property.type === "Identifier" && node.callee.property.name === "call") {
              var functionType = tern.expressionType({ node: node.callee.object, state: scope }).getFunctionType();
              if (functionType && toReplace.indexOf(functionType.originNode) !== -1) {
                return util.call(
                  node.callee.object,
                  node.arguments
                );
              }
            } else if (node.type === "CallExpression" && node.callee.type === "MemberExpression") {
              var functionType = tern.expressionType({ node: node.callee, state: scope }).getFunctionType();
              if (functionType && toReplace.indexOf(functionType.originNode) !== -1) {
                if (!guaranteedNoSideEffects(node.callee))
                  return makeCallerIIFE(node.callee, node.arguments);
                return util.call(
                  deepClone(node.callee),
                  [node.callee.object].concat(node.arguments)
                );
              }
            } else if (node.type === "CallExpression") {
              return util.call(
                deepClone(node.callee),
                [util.identifier("undefined")].concat(node.arguments)
              );
            }
          }
        });
      });
    }
    function deepClone(object) {
      return JSON.parse(JSON.stringify(object));
    }
    function guaranteedNoSideEffects(node) {
      if (node.type == "Identifier") return true;
      if (node.type == "MemberExpression" && !node.computed) return guaranteedNoSideEffects(node.object);
      return false;
    }
    function makeCallerIIFE(membex, callArguments) {
      return util.iifeWithArguments({
        callee: membex.object
      }, {
        id: "selfCallerIIFE",
        bodyExpr: util.call(
          util.member("callee", membex.property, membex.computed),
          ["callee"].concat(callArguments)
        )
      });
    }
  }
});

// lib/depropinator.js
var require_depropinator = __commonJS({
  "lib/depropinator.js"(exports2, module2) {
    "use strict";
    var estraverse = require("estraverse");
    var assert = require("assert");
    var util = require_util();
    module2.exports = function depropinator(ast) {
      estraverse.replace(ast, {
        leave: (node) => {
          if (node.type !== "ObjectExpression" || !node.properties.length) {
            return;
          }
          return makeIIFEThatAssignsEachProperty(node);
        }
      });
    };
    function makeIIFEThatAssignsEachProperty(node) {
      const assignments = node.properties.map(
        (prop) => util.expressionStatement(
          util.assignment(
            util.member(
              "ret",
              prop.key,
              /*computed=*/
              prop.key.type !== "Identifier"
            ),
            prop.value
          )
        )
      );
      return util.iife([
        util.declaration("ret", util.object()),
        ...assignments,
        util.return(util.identifier("ret"))
      ]);
    }
  }
});

// lib/deregexenise.js
var require_deregexenise = __commonJS({
  "lib/deregexenise.js"(exports2, module2) {
    "use strict";
    var estraverse = require("estraverse");
    var util = require_util();
    module2.exports = function deregexenise(ast) {
      estraverse.replace(ast, {
        enter: (node) => {
          if (node.regex) {
            const { pattern, flags } = node.regex;
            return util.new("RegExp", [
              util.literal(pattern),
              ...flags ? [util.literal(flags)] : []
            ]);
          }
        }
      });
      return ast;
    };
  }
});

// lib/ownfunction.coffee
var require_ownfunction = __commonJS({
  "lib/ownfunction.coffee"(exports2, module2) {
    (function() {
      var assert, estraverse, generate_ownfunction_iife, util;
      assert = require("assert");
      estraverse = require("estraverse");
      util = require_util();
      module2.exports = function(programNode) {
        var _usesOwnNameCache, usesOwnName, visited;
        _usesOwnNameCache = /* @__PURE__ */ new Map();
        usesOwnName = function(functionNode) {
          var functionName, ret;
          if (_usesOwnNameCache.has(functionNode)) {
            return _usesOwnNameCache.get(functionNode);
          }
          functionName = functionNode.id.name;
          ret = false;
          estraverse.traverse(functionNode, {
            enter: function(node, parent) {
              if (node === functionNode || node === functionNode.id) {
                return;
              }
              if (node.type === "Identifier" && node.name === functionName) {
                ret = true;
                return this.break();
              }
            }
          });
          _usesOwnNameCache.set(functionNode, ret);
          return ret;
        };
        visited = /* @__PURE__ */ new Set();
        return estraverse.replace(programNode, {
          enter: function(node, parent) {
            if (!/^Function/.test(node.type) || visited.has(node) || !node.id) {
              return;
            }
            if (!usesOwnName(node)) {
              return;
            }
            visited.add(node);
            if (/Declaration/.test(node.type)) {
              return util.declaration(node.id.name, generate_ownfunction_iife(node));
            }
            return generate_ownfunction_iife(node);
          }
        });
      };
      generate_ownfunction_iife = function(func) {
        func.type = "FunctionDeclaration";
        return util.iife([func, util.return(util.identifier(func.id.name))]);
      };
    }).call(exports2);
  }
});

// lib/index.coffee
(function() {
  var assert, astValidator, basicTransforms, bindify, child_process, clean_ast, declosurify, depropinator, deregexenise, dumbify, dumbifyAST, escodegen, escope, estraverse, fs, mainify, ownfunction, parse, requireObliteratinator, thatter, topmost, typeConversions, util;
  fs = require("fs");
  assert = require("assert");
  escope = require("escope");
  escodegen = require("escodegen");
  estraverse = require("estraverse");
  child_process = require("child_process");
  astValidator = require_check_ast();
  parse = require_parse();
  basicTransforms = require_basic_transforms();
  requireObliteratinator = require_require_obliteratinator();
  typeConversions = require_type_conversions();
  topmost = require_topmost();
  declosurify = require_declosurify();
  bindify = require_bindify();
  mainify = require_mainify();
  thatter = require_thatter();
  depropinator = require_depropinator();
  deregexenise = require_deregexenise();
  ownfunction = require_ownfunction();
  util = require_util();
  clean_ast = function(ast) {
    return estraverse.traverse(ast, {
      leave: function(node) {
        delete node.scope;
        return delete node.objType;
      }
    });
  };
  dumbifyAST = function(ast, opt = {}) {
    var isValid;
    ast = basicTransforms(ast);
    if (opt.requireObliteratinator !== false) {
      ast = requireObliteratinator(ast, Object.assign(Object.create(opt.obliterinatorOpts || {}), {
        filename: opt.filename || "",
        transformRequiredModule: basicTransforms
      }));
      clean_ast(ast);
    }
    if (opt.deregexenise !== false) {
      ast = deregexenise(ast);
      clean_ast(ast);
    }
    if (opt.typeConversions !== false) {
      typeConversions(ast, opt.typeConversions || {});
      clean_ast(ast);
    }
    if (opt.mainify !== false) {
      mainify(ast, opt.mainify || {});
      clean_ast(ast);
    }
    if (opt.thatter !== false) {
      thatter(ast);
      clean_ast(ast);
    }
    if (opt.depropinator !== false) {
      depropinator(ast);
      clean_ast(ast);
    }
    if (opt.declosurify !== false) {
      ownfunction(ast);
      clean_ast(ast);
      declosurify(ast);
      clean_ast(ast);
    }
    if (opt.topmost !== false) {
      topmost(ast);
      clean_ast(ast);
    }
    if (opt.bindify !== false) {
      bindify(ast);
      clean_ast(ast);
    }
    isValid = astValidator(ast);
    if (isValid !== true) {
      throw isValid;
    }
    return ast;
  };
  dumbify = function(js, opt = {}) {
    var ast, bind, mayContainRequire, text;
    mayContainRequire = /require\s*?\(/m.test(js);
    ast = parse(js, opt.filename);
    if (mayContainRequire === false) {
      opt.requireObliteratinator = false;
    }
    ast = dumbifyAST(ast, opt);
    text = escodegen.generate(ast, {
      comment: true
    });
    if (opt.esmCompat === true) {
      bind = bindify.name(opt);
      text = `import {BIND as ${bind},JS_ADD} from "special:dumbjs"
` + text;
    }
    return text;
  };
  module.exports = dumbify;
  module.exports.dumbify = dumbify;
  module.exports.dumbifyAST = dumbifyAST;
  module.exports.enableTestMode = util.enableTestMode;
}).call(exports);
