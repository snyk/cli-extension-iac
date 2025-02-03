package git_test

import (
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	goGit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/snyk/cli-extension-iac/internal/git"
	"github.com/stretchr/testify/require"
)

func TestList(t *testing.T) {
	root, repo := initRepository(t)

	start := time.Now()

	commit(t, root, repo, "author-1@example.com", start.Add(1*time.Hour))
	commit(t, root, repo, "author-2@example.com", start.Add(2*time.Hour))

	c, err := git.ListContributors(root, start, start.Add(3*time.Hour), 2)
	require.NoError(t, err)

	requireContributors(t, c, []git.Contributor{
		{
			Email:          "author-1@example.com",
			LastCommitDate: start.Add(1 * time.Hour),
		},
		{
			Email:          "author-2@example.com",
			LastCommitDate: start.Add(2 * time.Hour),
		},
	})
}

func TestListMostRecentDate(t *testing.T) {
	root, repo := initRepository(t)

	start := time.Now()

	commit(t, root, repo, "author@example.com", start.Add(1*time.Hour))
	commit(t, root, repo, "author@example.com", start.Add(2*time.Hour))

	contributors, err := git.ListContributors(root, start, start.Add(3*time.Hour), 2)
	require.NoError(t, err)

	requireContributors(t, contributors, []git.Contributor{
		{
			Email:          "author@example.com",
			LastCommitDate: start.Add(2 * time.Hour),
		},
	})
}

func TestListMaxLessThanCommits(t *testing.T) {
	root, repo := initRepository(t)

	start := time.Now()

	commit(t, root, repo, "author-1@example.com", start.Add(1*time.Hour))
	commit(t, root, repo, "author-2@example.com", start.Add(2*time.Hour))

	contributors, err := git.ListContributors(root, start, start.Add(3*time.Hour), 1)
	require.NoError(t, err)

	requireContributors(t, contributors, []git.Contributor{
		{
			Email:          "author-2@example.com",
			LastCommitDate: start.Add(2 * time.Hour),
		},
	})
}

func TestListMaxMoreThanCommits(t *testing.T) {
	root, repo := initRepository(t)

	start := time.Now()

	commit(t, root, repo, "author-1@example.com", start.Add(1*time.Hour))
	commit(t, root, repo, "author-2@example.com", start.Add(2*time.Hour))

	contributors, err := git.ListContributors(root, start, start.Add(3*time.Hour), 3)
	require.NoError(t, err)

	requireContributors(t, contributors, []git.Contributor{
		{
			Email:          "author-1@example.com",
			LastCommitDate: start.Add(1 * time.Hour),
		},
		{
			Email:          "author-2@example.com",
			LastCommitDate: start.Add(2 * time.Hour),
		},
	})
}

func TestListOrderIncreasing(t *testing.T) {
	root, repo := initRepository(t)

	start := time.Now()

	commit(t, root, repo, "aaa@example.com", start.Add(1*time.Hour))
	commit(t, root, repo, "zzz@example.com", start.Add(2*time.Hour))

	contributors, err := git.ListContributors(root, start, start.Add(3*time.Hour), 2)
	require.NoError(t, err)

	requireContributors(t, contributors, []git.Contributor{
		{
			Email:          "aaa@example.com",
			LastCommitDate: start.Add(1 * time.Hour),
		},
		{
			Email:          "zzz@example.com",
			LastCommitDate: start.Add(2 * time.Hour),
		},
	})
}

func TestListOrderDecreasing(t *testing.T) {
	root, repo := initRepository(t)

	start := time.Now()

	commit(t, root, repo, "zzz@example.com", start.Add(1*time.Hour))
	commit(t, root, repo, "aaa@example.com", start.Add(2*time.Hour))

	contributors, err := git.ListContributors(root, start, start.Add(3*time.Hour), 2)
	require.NoError(t, err)

	requireContributors(t, contributors, []git.Contributor{
		{
			Email:          "aaa@example.com",
			LastCommitDate: start.Add(2 * time.Hour),
		},
		{
			Email:          "zzz@example.com",
			LastCommitDate: start.Add(1 * time.Hour),
		},
	})
}

func initRepository(t *testing.T) (string, *goGit.Repository) {
	t.Helper()

	root := t.TempDir()

	repo, err := goGit.PlainInit(root, false)
	require.NoError(t, err)

	return root, repo
}

func commit(t *testing.T, root string, repo *goGit.Repository, email string, when time.Time) {
	t.Helper()

	err := os.WriteFile(filepath.Join(root, "file"), []byte(strconv.Itoa(rand.Int())), 0644)
	require.NoError(t, err)

	workTree, err := repo.Worktree()
	require.NoError(t, err)

	_, err = workTree.Add("file")
	require.NoError(t, err)

	commit, err := workTree.Commit("current date", &goGit.CommitOptions{
		Author: &object.Signature{
			Email: email,
			When:  when,
		},
		Committer: &object.Signature{
			Email: "committer@example.com",
			When:  when,
		},
	})
	require.NoError(t, err)

	_, err = repo.CommitObject(commit)
	require.NoError(t, err)
}

func requireContributors(t *testing.T, got, expected []git.Contributor) {
	require.Len(t, got, len(expected))

	for i := range expected {
		require.Equal(t, expected[i].Email, got[i].Email)
		require.Equal(t, expected[i].LastCommitDate.Unix(), got[i].LastCommitDate.Unix())
	}
}
