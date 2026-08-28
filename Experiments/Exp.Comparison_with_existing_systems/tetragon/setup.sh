helm install tetragon ${EXTRA_HELM_FLAGS[@]} cilium/tetragon -n kube-system 
helm upgrade tetragon cilium/tetragon -n kube-system --reuse-values \
  --set export.mode="" --set export.stdout.enabled=null

k apply -f policy.yaml

# master node
./exe_v1.sh setup 1     # 사이드카 제거, CPU 예산, ConfigMap, 롤아웃
./exe_v1.sh verify 1    # 클러스터 설정 검증

# worker node
./exe_v1.sh check 1     # 로그 상태 / 이벤트 타입 분포 / 파드 분포
sudo truncate -s 0 /var/run/cilium/tetragon/tetragon.log
./exe_v1.sh reset 30 && ./exe_v1.sh start 30

#   ... 워크로드 실행 ... in master node
./postmark.sh default sys-gen sys-gen

# worker node
DRAIN_STABLE_SEC=30 ./exe_v1.sh stop 30

# 
kubectl scale deploy/sys-gen -n default --replicas=20