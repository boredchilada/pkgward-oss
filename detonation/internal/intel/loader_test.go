package intel

import (
	"reflect"
	"testing"
)

// TestMergeNoiseCoversEveryField guards against the silent-drop class: a []string
// field added to NoiseFilters but forgotten in mergeNoise would be zeroed by the
// baseline+overlay merge (this is exactly how abuse_hosts was lost). We set every
// field to distinct base/overlay sentinels and assert the merge unions both into
// every field.
func TestMergeNoiseCoversEveryField(t *testing.T) {
	var base, overlay NoiseFilters
	bv, ov := reflect.ValueOf(&base).Elem(), reflect.ValueOf(&overlay).Elem()
	for i := 0; i < bv.NumField(); i++ {
		if bv.Field(i).Kind() != reflect.Slice {
			continue
		}
		bv.Field(i).Set(reflect.ValueOf([]string{"base-sentinel"}))
		ov.Field(i).Set(reflect.ValueOf([]string{"overlay-sentinel"}))
	}

	merged := mergeNoise(base, overlay)
	mv := reflect.ValueOf(merged)
	mt := mv.Type()
	for i := 0; i < mv.NumField(); i++ {
		if mv.Field(i).Kind() != reflect.Slice {
			continue
		}
		got, _ := mv.Field(i).Interface().([]string)
		if len(got) != 2 {
			t.Errorf("mergeNoise drops field %s: got %v (want both base+overlay sentinels) — "+
				"add it to mergeNoise", mt.Field(i).Name, got)
		}
	}
}
