# [m-k8s]
./exe_v1.sh setup 30
#   check hostPath / config / policy scope in the verify output

# worker node
./exe_v1.sh check 30       
./exe_v1.sh reset 30
./exe_v1.sh start 30

# [m-k8s]
./postmark.sh default sys-gen sys-gen

# [w-1] after the workload finishes
DRAIN_STABLE_SEC=30 ./exe_v1.sh stop 30
sudo ./build/read_counter

#
kubectl scale deploy/sys-gen -n default --replicas=20