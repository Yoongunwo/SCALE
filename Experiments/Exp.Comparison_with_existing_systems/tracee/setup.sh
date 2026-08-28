# [m-k8s]
./exe_v1.sh setup 30
#   verify 출력에서 hostPath / config / policy scope 확인

# worker node
./exe_v1.sh check 30       
./exe_v1.sh reset 30
./exe_v1.sh start 30

# [m-k8s]
./postmark.sh default sys-gen sys-gen

# [w-1] 워크로드 완료 후
DRAIN_STABLE_SEC=30 ./exe_v1.sh stop 30
sudo ./build/read_counter

#
kubectl scale deploy/sys-gen -n default --replicas=20