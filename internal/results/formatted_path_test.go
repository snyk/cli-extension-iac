package results

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFormattedPath(t *testing.T) {
	tests := []struct {
		name       string
		ruleId     string
		resourceId string
		paths      []any
		output     string
	}{
		{
			"rule that requires an input. prefix",
			"SNYK-CC-TF-2",
			"aws_s3_bucket.name",
			[]any{},
			"input.resource.aws_s3_bucket[name]",
		},
		{
			"module in resourceId",
			"SNYK-CC-BLAH-1",
			"module.name.aws_s3_bucket.name",
			[]any{},
			"resource.aws_s3_bucket[name]",
		},
		{
			"int index inside the resource resourceId",
			"SNYK-CC-BLAH-1",
			"aws_s3_bucket.name[0][1]",
			[]any{1},
			`resource.aws_s3_bucket[name["0"]["1"]][1]`,
		},
		{
			"string index without quotes inside the resource resourceId",
			"SNYK-CC-BLAH-1",
			`aws_s3_bucket.name[test]`,
			[]any{1},
			`resource.aws_s3_bucket[name[test]][1]`,
		},
		{
			"string index with quotes inside the resource resourceId",
			"SNYK-CC-BLAH-1",
			`aws_s3_bucket.name["test"]`,
			[]any{1},
			`resource.aws_s3_bucket[name["test"]][1]`,
		},
		{
			"int inside path",
			"SNYK-CC-BLAH-1",
			"aws_s3_bucket.name",
			[]any{1},
			"resource.aws_s3_bucket[name][1]",
		}, {
			"float inside path",
			"SNYK-CC-BLAH-1",
			"aws_s3_bucket.name",
			[]any{1.0},
			"resource.aws_s3_bucket[name][1]",
		},
		{
			"string at the start of path",
			"SNYK-CC-BLAH-1",
			"aws_s3_bucket.name",
			[]any{"a"},
			"resource.aws_s3_bucket[name].a",
		},
		{
			"string anywhere else in path",
			"SNYK-CC-BLAH-1",
			"aws_s3_bucket.name",
			[]any{1, "a"},
			"resource.aws_s3_bucket[name][1].a",
		},
		{
			"resourceId for a module",
			"SNYK-CC-BLAH-1",
			"module.name.aws_s3_bucket.name",
			[]any{1, "a"},
			"resource.aws_s3_bucket[name][1].a",
		},
		{
			"resourceId does not have the right format",
			"SNYK-CC-BLAH-1",
			"aws_s3_bucket",
			[]any{1, "a"},
			"resource.aws_s3_bucket[1].a",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.output, formattedPath(test.ruleId, test.resourceId, test.paths))
		})
	}
}
