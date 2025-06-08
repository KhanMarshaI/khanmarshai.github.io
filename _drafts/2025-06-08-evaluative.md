---
title: "Evaluative"
date: 2025-06-08 3:29:00 +0500
categories: [Challenges]
tags: [HTB, Coding]
---

# Problem

Looking at the problem statement we can easily tell it's a polynomial evaluation problem.
![alt text](/assets/images/evaluative-statement.png)

# Approach
## Bruteforce
We could calculate polynomials with an O(n^2) approach. Nested for loops, where the outer loops add the coefficient to results and inner loop calculates power of x. 

## Horner's Rule
Horner's rule is an O(n) appraoch. It essentially opens up the calculation in this manner:
From: ax^2 + bx + 1
To: x(ax + b) + 1

# Solution
One thing to consider is the possibility of result getting too large to store in a 32bit space. Hence, we use `long long int` to store upto 64bit of integer value.

The coefficients are inserted in order x^0 to x^(n-1), hence, we store from the last index to first index. 

```cpp
#include <iostream>
using namespace std;

long long int horner(int coeff[], int x){
    long long int result = coeff[0]; //start from the inner most bracket (ax + b). store coefficient `a` in results

    for(int i=1; i<9; i++){
        result = result*x + coeff[i]; //do (ax + b)
        //suppose c = (ax + b)
        //in next iteration it does c*x + d
    }

    return result;
}

int main() {

    int coeff[9]; //array to store coefficient. each coefficient at ith index represents the coefficient of ith term.
    int x;
    
    //start from last index (x^0th) term to first index (x^n-1) term.
    for(int i=8; i>=0; i--){
        cin >> coeff[i];
    }
    cin >> x;
    
    cout << horner(coeff, x);

    return 0;
}
```
