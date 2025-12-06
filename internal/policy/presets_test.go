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
