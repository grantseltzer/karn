package karn

import (
	"reflect"
)

type MockWriter struct {
	// Fields for holding written info
	Internal []byte
}

func (mw *MockWriter) GetOutput() []byte {
	return mw.Internal
}

func (mw *MockWriter) Write(p []byte) (int, error) {
	mw.Internal = p
	return len(p), nil
}

func NewMockWriter() *MockWriter {
	x := MockWriter{}
	return &x
}

func (mw *MockWriter) CorrectOutput(correct []byte) bool {
	return reflect.DeepEqual(mw.Internal, correct)
}
