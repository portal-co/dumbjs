'use strict'

var assert = require('assert')
var escope = require('escope')
var estraverse = require('estraverse')
var util = require('./util')

module.exports = function (programNode, options) {
  var bindFunctionName = (options && options.bindFunctionName) || 'BIND'
  var toWrap = new Map()  // Map of func => closureName
  var scopeMan = escope.analyze(programNode)
  var scopeStack = [ scopeMan.acquire(programNode) ]  // From outermost to innermost, the lexical scopes
  var currentScope = function () { return scopeStack[scopeStack.length - 1] }

  estraverse.traverse(programNode, {
    enter: function (node, parent) {
      if (util.isFunction(node)) {
        var scope = scopeMan.acquire(node)
        if (scope.type === 'function-expression-name') {
          scope = scope.childScopes[0]
        }
        scopeStack.push(scope)
        return
      }
      if (node.type === 'Identifier' &&
          /^_flatten_/.test(node.name) &&
          !util.isFunction(parent) &&
          !(parent.type === 'VariableDeclarator' && parent.id === node)) {
        var closure = currentScope().variables.filter(function (p) { return /^_closure_/.test(p.name) })[0]
        if (closure && funcNeedsBind(programNode, node.name)) {
          toWrap.set(node, closure.name)
        }
      }
    },
    leave: function (node) {
      if (util.isFunction(node)) {
        scopeStack.pop()
      }
    }
  })

  estraverse.replace(programNode, {
    leave: function (node, parent) {
      if (node.type === 'Identifier' &&
          toWrap.has(node) &&
          !(parent.type === 'CallExpression' && parent.callee === node)
      ) {
        var closureName = toWrap.get(node)
        if (closureName) {
          return util.call(bindFunctionName, [node, util.identifier(closureName)])
        }
      }
      if (node.type === 'CallExpression' && toWrap.has(node.callee)) {
        var closureName = toWrap.get(node.callee)
        return util.call(node.callee.name, [ util.identifier(closureName), ...node.arguments ])
      }
    }
  })
}
module.exports.name = function(options){
  var bindFunctionName = (options && options.bindFunctionName) || 'BIND'
  return bindFunctionName;
}

function funcNeedsBind(program, funcName) {
  var firstParam = funcByName(program, funcName).params[0]
  return firstParam && firstParam.name === '_closure'
}

function funcByName(program, needle) {
  return allFuncs(program.body)
    .filter(function (nodeAndName) { return nodeAndName.name === needle })
    [0].node
}

function allFuncs(body) {
  return body.map(getFuncDecl)
    .filter(decl => decl != null)
}

function getFuncDecl(node) {
  if (util.isFunction(node)) {
    return { node: node, name: node.id.name }
  }
  if (node.type === 'VariableDeclaration' &&
      util.isFunction(node.declarations[0].init)) {
    return { node: node.declarations[0].init, name: node.declarations[0].id.name }
  }
  return undefined
}

