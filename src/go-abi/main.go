// main.go
package main

import (
	"fmt"
	"time"
)

func main() {
	var v1, v2, v3 int64 = 2, 3, 4
	var str string = "cccccc"
	var b []byte = []byte(str)

	for {
		go foo(v1, v2, v3, b)
		time.Sleep(time.Second)
	}
}

//go:noinline
func foo(a1, a2, a3 int64, b []byte) (int64, []byte) {
	var b1, b2 int64 = 10, 20
	var c []byte = b
	if a1 > 6 {
		return a1, c
	}
	fmt.Printf("foo return :%d\n", a1*a3+a2*a3+b1*b2)
	return a1*a3 + a2*a3 + b1*b2, c
}
