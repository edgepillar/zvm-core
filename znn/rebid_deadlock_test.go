package znn

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// publish takes a.mu; publishLocked runs with it already held. The re-bid path
// inside publishLocked rebuilds the block and retries, and it must retry into
// publishLocked — never into publish, which would take a.mu a second time on
// the same goroutine.
//
// sync.Mutex is not reentrant, so that self-deadlocks the account permanently,
// and because it is a lock rather than an I/O wait no context deadline can
// break it: the caller never returns. It only reaches that branch on a chain
// with dynamic plasma under enough load to move the plasma price, which is why
// it survived every test and every run on chain 70 and only surfaced when the
// native lane was offered more than it could carry on chain 71.
//
// A unit test cannot call publish without a node, so this asserts the invariant
// against the source itself, which is the thing that actually has to hold.
func TestPublishLockedNeverCallsPublish(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "account.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	var checked bool
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != "publishLocked" {
			continue
		}
		checked = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "publish" {
				t.Errorf("%s: publishLocked calls publish, which re-locks a.mu on the same goroutine and deadlocks the account; call publishLocked instead",
					fset.Position(call.Pos()))
			}
			// Taking the lock again inside the locked section is the same bug
			// by another route.
			if sel.Sel.Name == "Lock" && strings.Contains(exprText(fset, sel.X), "mu") {
				t.Errorf("%s: publishLocked takes a lock it is already holding", fset.Position(call.Pos()))
			}
			return true
		})
	}
	if !checked {
		t.Fatal("publishLocked not found in account.go: if publish was restructured, this guard needs updating rather than deleting")
	}
}

func exprText(fset *token.FileSet, e ast.Expr) string {
	var sb strings.Builder
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			sb.WriteString(id.Name)
			sb.WriteString(".")
		}
		return true
	})
	return sb.String()
}
