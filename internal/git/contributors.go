package git

import (
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/go-git/go-git/v5"
)

// Contributor is a contributor of a repository.
type Contributor struct {
	Email          string    `json:"email"`
	LastCommitDate time.Time `json:"lastCommitDate"`
}

// ListContributors scans the Git log and computes a list of the most recent
// contributors. path is the path of the Git repository. since and until
// restrict the search to commits falling in that time range. max caps the
// amount of commits to process. ListContributors returns a slice of
// [Contributor], sorted by email.
func ListContributors(path string, since, until time.Time, max int) ([]Contributor, error) {
	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err == git.ErrRepositoryNotExists {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open repository: %v", err)
	}

	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("read head: %v", err)
	}

	iter, err := repo.Log(&git.LogOptions{
		From:  head.Hash(),
		Since: &since,
		Until: &until,
	})
	if err != nil {
		return nil, fmt.Errorf("read log: %v", err)
	}

	defer iter.Close()

	authors := make(map[string]time.Time)

	for i := 0; i < max; i++ {
		commit, err := iter.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read commit: %v", err)
		}

		var (
			email = commit.Author.Email
			when  = commit.Author.When
		)

		if prev, ok := authors[email]; ok {
			if when.Before(prev) {
				continue
			}
		}

		authors[email] = when
	}

	var contributors []Contributor

	for email, lastCommitDate := range authors {
		contributors = append(contributors, Contributor{
			Email:          email,
			LastCommitDate: lastCommitDate,
		})
	}

	sort.Sort(byEmail(contributors))

	return contributors, nil
}

type byEmail []Contributor

var _ sort.Interface = byEmail{}

func (c byEmail) Len() int {
	return len(c)
}

func (c byEmail) Less(i, j int) bool {
	return c[i].Email < c[j].Email
}

func (c byEmail) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}
