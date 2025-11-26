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

func TestKubectlPreset(t *testing.T) {
	expect(t, Allow,
		"kubectl get pods",
		"kubectl logs pod-1 --tail 100",
		"kubectl config current-context",
		"kubectl version",
		"kubectl auth can-i list pods",
		"oc get pods",
	)
	expect(t, Confirm,
		"kubectl apply -f x.yaml",
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
		"kubectl drain node-1",
		"kubectl replace --force -f x.yaml",
		"kubectl apply --prune -f x.yaml",
		"kubectl config delete-context x",
		"oc delete pod x",
		"kubecolor delete pod x",
		"kubectl frobnicate",
	)
}

func TestTerraformPreset(t *testing.T) {
	expect(t, Allow,
		"terraform plan",
		"terraform show",
		"terraform validate",
		"terraform output -json",
		"terraform state list",
		"terraform fmt -check",
		"terraform version",
		"tofu plan",
	)
	expect(t, Confirm,
		"terraform apply",
		"terraform init",
		"terraform fmt",
		"terraform state mv a b",
		"tofu apply",
	)
	expect(t, Deny,
		"terraform destroy",
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
