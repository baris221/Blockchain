#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../key/keyH.h"
#include "../primal/primalH.h"


void delete_string(void* str)
{
	if (!str)
	{
		printf("[delete_string Function] Erreur str is NULL\n");
		return;
	}

	free(str);
	return;
}

long extended_gcd(long s,long t,long *u,long *v)
{
	if (s==0)
	{
		*u=0;
    	*v=1;
    	return t;
  	}

  	long uPrim, vPrim ;
  	long gcd = extended_gcd(t%s,s,&uPrim,&vPrim);
  	*u=vPrim-(t/s)*uPrim;
  	*v=uPrim;
	return gcd;
}


void generate_key_values(long p,long q, long *n, long *s,long *u)
{
	*n = p * q;
	long t = (p-1) * (q-1);
  	*s = rand_long(0, t);
  	long v=0;

  	while(extended_gcd(*s, t, u, &v) != 1)
	{
    	*s = rand_long(0, t);
  	}
}
    
long* encrypt(char* chaine, long s, long n)
{
	long *tab=malloc(sizeof(long)*strlen(chaine));
   if(!tab)
	{
     	printf("[Encrypt Function] Erreur Malloc \n");
     	return NULL;
   }
    	
 	for (int i = 0; i < strlen(chaine); i++){
   	tab[i]=modpow((long)chaine[i], s, n);  		
 	}
    	
	return tab;
} 

char* decrypt(long* crypted, int size, long u, long n)
{	
	char* resultString = (char *) malloc(sizeof(char) * (size+1));
	if(!resultString)
	{
     	printf("[Decrypt Function] Erreur Malloc \n");
     	return NULL;
   }

	int i;

  	for(i = 0; i < size; i++)
	{
    	resultString[i] = (char) modpow(crypted[i], u, n);
  	}

  	resultString[i] = '\0';

  	return resultString;
}

void print_long_vector(long *result , int size)
{ 
	printf ("Vector: [ "); 
  	for(int i =0; i < size ; i ++)
	{
    	printf("%lx \t", result [i]);
  	} 
  	printf ("] \n");
}