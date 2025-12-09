package policy

import (
	"testing"
)

func loadDefault(t testing.TB) *Policy {
	t.Helper()
	p, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// expect checks a table of commands against one decision.
func expect(t *testing.T, want Decision, commands ...string) {
	t.Helper()
	p := loadDefault(t)
	for _, c := range commands {
		rep := p.Evaluate(c, Options{CWD: "/work"})
		if rep.Decision != want {
			t.Errorf("%q: got %s, want %s\n  %s", c, rep.Decision, want, rep.Reason())
		}
	}
}

func TestGitPreset(t *testing.T) {
	expect(t, Allow,
		"git status",
		"git log --oneline -5",
		"git log --format=%H --since=yesterday",
		"git diff HEAD~1",
		"git show HEAD:README.md",
		"git blame main.go",
		"git branch",
		"git branch -a",
		"git branch --show-current",
		"git branch --list 'fix/*'",
		"git tag",
		"git tag -l 'v*'",
		"git remote -v",
		"git remote get-url origin",
		"git stash list",
		"git rev-parse HEAD",
		"git fetch origin",
		"git config --get user.name",
		"git config --list",
		"git --no-pager log",
		"git -C /tmp/repo status",
		"git --version",
		"git clean -n",
		"/usr/bin/git status",
		"LC_ALL=C git status",
	)
	expect(t, Confirm,
		"git add .",
		`git commit -m "fix the thing"`,
		"git push",
		"git push -u origin main",
		"git push origin main",
		"git pull",
		"git checkout -b feature",
		"git checkout main",
		"git switch main",
		"git merge feature",
		"git rebase main",
		"git stash",
		"git stash pop",
		"git tag v1.0.0",
		"git branch feature",
		"git reset HEAD~1",
		"git reset --soft HEAD~1",
		"git restore --staged a.txt",
		"git remote add fork url",
		"git -C /tmp/repo push",
	)
	expect(t, Deny,
		"git push --force",
		"git push -f",
		"git push -fu origin main",
		"git push origin main --force",
		"git push --forc",
		"git push --force-with-lease",
		"git push --mirror",
		"git push --delete origin main",
		"git push -d origin main",
		"git push origin :main",
		"git push origin +main",
		"git -C /tmp push --force",
		"git --git-dir=.git push -f",
		"git --no-pager push --force",
		"git reset --hard",
		"git reset --hard HEAD~3",
		"git clean -fd",
		"git clean -fdx",
		"git branch -D feature",
		"git branch -d feature",
		"git branch --delete feature",
		"git tag -d v1",
		"git checkout -- .",
		"git checkout .",
		"git checkout -f main",
		"git restore a.txt",
		"git rm a.txt",
		"git filter-branch --all",
		"git stash drop",
		"git stash clear",
		"git reflog expire --all",
		"git update-ref -d HEAD",
		"git gc --prune=now",
		"git prune",
		"git commit -nm x",
		"git log --output=/tmp/x",
		"git diff --ext-diff",
		"git grep -Ovim foo",
		"git config core.sshCommand evil",
		"git --unknown-flag log",
	)
}

func TestGhPreset(t *testing.T) {
	expect(t, Allow,
		"gh pr list",
		"gh pr diff 12",
		"gh repo view",
		"gh run list",
		"gh search repos seatbelt",
		"gh auth status",
		"gh --version",
	)
	expect(t, Confirm,
		"gh pr merge 12",
		"gh release create v1",
		"gh workflow run ci.yml",
	)
	expect(t, Deny,
		"gh repo delete o/r --yes",
		"gh release delete v1",
		"gh issue delete 3",
		"gh gist delete abc",
		"gh run delete 1",
		"gh secret delete X",
		"gh label delete x",
		"gh auth token",
		"gh repo archive o/r",
		"gh something new",
	)
}

func TestKubectlPreset(t *testing.T) {
	expect(t, Allow,
		"kubectl get pods",
		"kubectl get pods -n kube-system -o yaml",
		"kubectl --context prod get pods",
		"kubectl -n prod describe pod x",
		"kubectl logs pod-1 --tail 100",
		"kubectl config current-context",
		"kubectl version",
		"kubectl auth can-i list pods",
		"oc get pods",
	)
	expect(t, Confirm,
		"kubectl apply -f x.yaml",
		"kubectl -n prod apply -f x.yaml",
		"kubectl scale deploy x --replicas=3",
		"kubectl rollout restart deploy x",
		"kubectl exec -it pod -- sh",
		"kubectl get secret x -o yaml",
		"kubectl get secrets",
		"kubectl get secret/x",
		"kubectl describe secret x",
		"kubectl config view --raw",
	)
	expect(t, Deny,
		"kubectl delete pod x",
		"kubectl delete ns prod",
		"kubectl --context prod delete pod x",
		"kubectl -n prod delete pod x",
		"kubectl --namespace=prod delete pod x",
		"kubectl drain node-1",
		"kubectl replace --force -f x.yaml",
		"kubectl apply --prune -f x.yaml",
		"kubectl config delete-context x",
		"oc delete pod x",
		"kubecolor delete pod x",
		"kubectl frobnicate",
		"kubectl --unknown-flag get pods",
	)
}

func TestTerraformPreset(t *testing.T) {
	expect(t, Allow,
		"terraform plan",
		"terraform plan -var-file=prod.tfvars",
		"terraform show",
		"terraform validate",
		"terraform output -json",
		"terraform state list",
		"terraform -chdir=infra plan",
		"terraform fmt -check",
		"terraform version",
		"tofu plan",
	)
	expect(t, Confirm,
		"terraform apply",
		"terraform apply plan.out",
		"terraform init",
		"terraform -chdir=infra apply",
		"terraform fmt",
		"terraform state mv a b",
		"tofu apply",
	)
	expect(t, Deny,
		"terraform destroy",
		"terraform -chdir=infra destroy",
		"terraform destroy -auto-approve",
		"terraform apply -destroy",
		"terraform apply --destroy",
		"terraform apply -auto-approve",
		"terraform apply --auto-approve",
		"terraform state rm x",
		"terraform workspace delete prod",
		"terraform force-unlock 123",
		"tofu destroy",
		"terraform unknown",
	)
}
