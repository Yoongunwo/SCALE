for pod in $(kubectl get pods -o custom-columns=NAME:.metadata.name --no-headers | grep '^exp2-'); do
    start=$(kubectl exec -c proxy "$pod" -- sh -c "head -n 1 syscall_log.txt" | awk '{print $1}')
    end=$(kubectl exec -c proxy "$pod" -- sh -c "tail -n 2 syscall_log.txt | head -n 1" | awk '{print $1}')
    dur=$(awk "BEGIN {printf \"%.3f\", $end - $start}")
    count=$(kubectl exec -c proxy "$pod" -- sh -c "wc -l < syscall_log.txt")
    printf "%-10s  duration: %7s sec   lines: %s\n" "$pod" "$dur" "$count"
done

for pod in $(kubectl get pods -o custom-columns=NAME:.metadata.name --no-headers | grep '^node2'); do
    start=$(kubectl exec -c proxy "$pod" -- sh -c "head -n 1 syscall_log.txt" | awk '{print $1}')
    end=$(kubectl exec -c proxy "$pod" -- sh -c "tail -n 2 syscall_log.txt | head -n 1" | awk '{print $1}')
    dur=$(awk "BEGIN {printf \"%.3f\", $end - $start}")
    count=$(kubectl exec -c proxy "$pod" -- sh -c "wc -l < syscall_log.txt")
    printf "%-10s  duration: %7s sec   lines: %s\n" "$pod" "$dur" "$count"
done