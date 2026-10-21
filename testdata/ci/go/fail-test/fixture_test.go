package fixture

import "testing"

func TestAdd(t *testing.T) {
	if got := Add(2, 2); got != 5 {
		t.Fatalf("Add(2, 2) = %d, want 5", got)
	}
}
