---
title: "Primed For Action"
date: 2025-06-09 12:50:00 +0500
categories: [Challenges]
tags: [HTB, Coding]
---

# Problem
The problem statement essentially points towards finding two prime numbers from given "n" numbers. Once we find the primes we just multiply and return the result.

![alt text](assets/images/primed-for-action.png)

# Approach

```cpp
#include <iostream>
#include <vector>
using namespace std;

int main() {
    int n;
    vector<int> nums;

    while(cin >> n){
        nums.push_back(n);
    }
    vector<int> primes;
    for(int i=0; i<nums.size(); i++){
        int cur = nums[i];
        if(cur==1 || cur == 0) continue;
        bool prime = true;
        for(int j=2; j< cur /2; j++){
            if(cur % j == 0) prime = false;
        }
        if(prime == true) primes.push_back(cur);
    }

    cout << primes[0] * primes[1] << endl;

    return 0;
}
```
