# generate syscall 
kubectl get pods -n default -l app=sys-gen -o name \
  | xargs -P 32 -I{} kubectl exec -n default {} -- kill -USR1 1


# generate syscall for scale
kubectl get pods -n default -l app=exp2 -o name \
  | xargs -P 32 -I{} kubectl exec -n default {} -c sys-gen -- kill -USR1 1

# generate syscall for distributed eBPF and scale
kubectl get pods -n default -l app=exp2 -o name \
  | xargs -P 32 -I{} kubectl exec -n default {} -c sys-gen -- \
      sh -c 'pkill -USR1 -x sys_generator'

# logging
kubectl logs -n default -l app=sys-gen --tail=-1 | grep '^CSV,' > result_baseline_N30.csv

# centralized eBPF logging
kubectl logs -n default -l app=sys-gen --tail=-1 | grep '^CSV,' > /tmp/all.csv
awk -F, 'NR==FNR{ if($4+0>m[$3]) m[$3]=$4+0; next } $4+0==m[$3]' \
    /tmp/all.csv /tmp/all.csv > result_central_N5.csv

# distributed eBPF logging
kubectl logs -n default -l app=exp2 -c sys-gen --tail=-1 | grep '^CSV,' > /tmp/all.csv
awk -F, 'NR==FNR{ if($4+0>m[$3]) m[$3]=$4+0; next } $4+0==m[$3]' \
    /tmp/all.csv /tmp/all.csv > result_distributed_N30.csv

# scale logging
kubectl logs -n default -l app=exp2 -c sys-gen --tail=-1 | grep '^CSV,' > /tmp/all.csv
awk -F, 'NR==FNR{ if($4+0>m[$3]) m[$3]=$4+0; next } $4+0==m[$3]' \
    /tmp/all.csv /tmp/all.csv > result_scale_N30.csv