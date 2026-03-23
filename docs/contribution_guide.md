# Contribution Guide

You should always use this guide in this project.

## Documentation

* All packages must have a Go docstring in the file `<package_name>.go` or in
the file `doc.go`.

* All exported symbols should be commented starting with the symbol name 
  followed by a phrase containing only complete sentences that explains the 
  **why** of this symbol, not the **what** — be it a constant, variable, type,
  function, method, etc.

## Formatting

* The line length must not exceed 80 characters, except in string literals, for
the reason of "greppability".

* Consider tab size as 8 spaces.

* Never wrap words — instead put the entire word in a new line.

* Code blocks should be separated by an empty line.

### Function Wrapping

* When a function definition does not fit in 80 columns, it should be wrapped.

* When a function is wrapped, the argument list closing parenthesis should be
  preceded by at least one argument, so there is no need to put `,` after the
  last argument.

* When wrapping an argument list, the wrapped lines should be indented, and the
  first line of the body block must be preceded by an empty line.

```go
func Name(param type, param type, param type, param type, param type,
	param type, param type) int {

	// logic
}
```

### Switch and Select

* Always put an empty line between switch and select statement cases.

Good:

```go
switch condition {
	case a:
		// logic

	case b:
		// logic

	case c:
		// logic

	default:
		// logic
}
```

Bad:

```go
switch condition {
	case a:
		// logic
	case b:
		// logic
	case c:
		// logic
	default:
		// logic
}
```

### Long `for and if` Conditions

* When the conditions of a conditional structure are wrapped, start the body
  block with an empty line.

Good:

```go
if condition &&
	condition &&
	condition &&
	condition &&
	condition &&
	condition {

	// logic
}
```

Bad:

```go
for condition &&
	condition &&
	condition &&
	condition &&
	condition &&
	condition {
	// logic
}
```

## Submiting Commits
* Max line length should be of 80 - 4 = 76 columns
* Commits must start with the subject of the commit, starting with the name of
  the subsystem or subsystems modified, followed by a short description of the
  commit
* If multiple subsistems were modified, separate the names with	`,`
* After the subject paragraph, there must be an empty line, and then, the full
  description of the commit
* Always run the test suite before commiting
* Every function added should be covered by tests
* No commit can break tests

### Examples:
Example 1:
```
subsystem: short description

Complete description
```
Example 2:
```
subsystem,subsystem2: short description

Complete description
```

## Testing
* The command `go test .` must always work, tests that that need setup should
  be skipped when the dependencies are not met, for example: missing api key or
  missing database connection configuration
* Use table tests when applyable, example:
```go
func TestAdd(t *testing.T) {
	tests := []struct{
		a int
		b int
		expected int
	}{
		{1, 2, 3},
		{2, 3, 5},
	}
	for i, test := range tests {
		r := Add(test.a, test.b)
		if r != test.expected {
			t.Fatal("unexpected result, a %d, b %d, expected %d, result %d",
				test.a, test.b, test.expected, r)
		}
	}
}
```
* Never add conditional setup/teardown in the table tests, if conditional setup
  or teardown is needed, write another test function. This keeps the code 
  understandable and maintainable
