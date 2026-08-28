# Evaluation for Sysdig

## 1. Method
1. run collector pod using `pod.yaml`
2. run generator pod using `config.yaml`
3. run `make` to build `./collector` for checking drop
4. run `Sysdig.txt` in the pod with `./collector`