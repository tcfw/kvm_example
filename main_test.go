package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	run(buf)

	assert.Equal(t, buf.Bytes(), []byte("4\n"))
}
