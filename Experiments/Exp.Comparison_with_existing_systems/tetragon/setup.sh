helm install tetragon ${EXTRA_HELM_FLAGS[@]} cilium/tetragon -n kube-system 
helm upgrade tetragon cilium/tetragon -n kube-system --reuse-values \
  --set export.mode="" --set export.stdout.enabled=null

k apply -f policy.yaml

# master node
./exe_v1.sh setup 1     # remove sidecars, CPU budget, ConfigMap, rollout
./exe_v1.sh verify 1    # verify the cluster configuration

# worker node
./exe_v1.sh check 1     # log status / event type distribution / pod distribution
sudo truncate -s 0 /var/run/cilium/tetragon/tetragon.log
./exe_v1.sh reset 30 && ./exe_v1.sh start 30

#   ... run the workload ... in master node
./postmark.sh default sys-gen sys-gen

# worker node
DRAIN_STABLE_SEC=30 ./exe_v1.sh stop 30

# 
kubectl scale deploy/sys-gen -n default --replicas=20