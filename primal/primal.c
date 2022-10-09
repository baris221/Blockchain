#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include "primalH.h"

int is_prime_naive(long p)
{
    for (int i = 3; i < p; i += 2)
	    if ((p%i) == 0)
	       	return 0;
	
	return 1;       
}


long modpow_naive(long a, long m, long n)
{
	long s = 1;
	for(long i = 0; i < m; i++)
	{
		s = s * a;
		s = s % n;
	}

	return s;
}

long modpow(long a,long m,long n)
{
	if (m == 1)
		return a%n;

	if( m % 2 == 0)
	{
		long b = modpow(a, m/2, n);
		return b * b % n;
	}
	else
	{
		long b = modpow(a, floor(m/2), n);
		return a * b * b % n;
	}
}

int witness(long a, long b, long d, long p) 
{
	long x = modpow(a,d,p);
	if (x == 1)
	{
		return 0;
	}

	for (long i = 0; i < b; i++)
	{
		if (x == p-1)
			return 0;

		x = modpow(x, 2, p);
	}
	return 1;
}

long rand_long(long low,long up)
{
	return rand() % (up - low + 1) + low;
}




int is_prime_miller(long p ,int k)
{
	if (p == 2) 
	{
		return 1;
	}

	if(!( p & 1) || p <= 1) //on verifie que p est impair et different de 1
	{ 
		return 0;
 	}

	//on determine b et d :
	long b = 0;
	long d = p - 1;
	while(!(d & 1)) //tant que d n’est pas impair
	{ 
		d = d / 2;
 		b = b + 1;
	}

	// On genere k valeurs pour a, et on teste si c’est un temoin :
	long a;
	int i;
	for(i = 0; i < k ; i++)
	{
		a = rand_long(2, p-1);
	
		if(witness(a, b, d, p)) 
			return 0;
	}
	return 1;
}

long random_prime_number(int low_size, int up_size, int k)
{  
	long p = rand_long(pow(2,low_size-1), pow(2,up_size)-1);

	while(is_prime_miller(p,k) == 0)
	{
		p = rand_long(pow(2, low_size-1), pow(2, up_size)-1);
  	}

  	return p;
}













