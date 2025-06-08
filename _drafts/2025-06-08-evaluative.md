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

```cpp
#include <iostream>
using namespace std;

long long int horner(int coeff[], int x){
    long long int result = coeff[0];

    for(int i=1; i<9; i++){
        result = result*x + coeff[i];
    }

    return result;
}

int main() {

    int coeff[9];
    int x;
    
    for(int i=8; i>=0; i--){
        cin >> coeff[i];
    }
    cin >> x;
    
    cout << horner(coeff, x);

    return 0;
}
```
