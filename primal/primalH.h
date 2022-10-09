#ifndef primalH_H
#define primalH_H

long modpow_naive(long a, long m, long n);
long modpow(long a, long m, long n);
int witness(long a, long b, long d, long p);
long rand_long(long low, long up);
int is_prime_miller(long p, int k);
long random_prime_number(int low_size, int up_size, int k);


#endif