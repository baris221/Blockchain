#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "../rsa/rsaH.h"
#include "../primal/primalH.h"
#include "../key/keyH.h"
#include "../signature/signatureH.h"
#include "../protected/protectedH.h"
#include "../cellkey/cellkeyH.h"
#include "../cellprotected/cellprotectedH.h"
#include "../hashtable/hashtableH.h"

HashCell* create_hashcell(Key* key)
{
	if(!key)
	{
		printf("[create_hashcell Function] Erreur Key is NULL\n");
		return NULL;
	}

	HashCell* newHashCell = (HashCell*) malloc(sizeof(HashCell));
	if (!newHashCell)
	{
		printf("[create_hashcell Function] Erreur Malloc newHashCell\n");
		return NULL;
	}

	newHashCell->key = key;
	newHashCell->val = 0;

	return newHashCell;
}

int hash_function(Key* key, int size)
{
	return (key->val) % size;
}

int find_position(HashTable* t, Key* key)
{
	if(!t || !key)
	{
		printf("[find_position Function] Erreur t OR key is NULL\n");
		return -1;
	}

	int keyIndex = hash_function(key, t->size);

	for (int i = 0; i < t->size; i++)
	{
		if (t && t->tab[i] && (t->tab[i]->key->val == key->val) && (t->tab[i]->key->n == key->n))
		{
			return i;
		}
	}

	return keyIndex;
}

HashTable* create_hashtable(CellKey* keys, int size)
{
	if (!keys)
	{
		printf("[create_hashtable Function] Erreur keys is NULL\n");
		return NULL;
	}

	CellKey* tempHead = keys;

	//Table qui va contenir les clés keys (Une clé par cellule) "Conversion liste chainée vers tableau par index de clés"
	HashCell** tab = (HashCell**) malloc(sizeof(HashCell*) * size);
	if (!tab)
	{
		printf("[create_hashtable Function] Erreur Malloc Table de Hachage is NULL\n");
		return NULL;
	}

	//On init la tableau à NULL
	for (int i = 0; i < size; i++)
		tab[i] = NULL;


	//Création de la structure de la table de hachage
	HashTable* newHashTable = (HashTable*) malloc(sizeof(HashTable));
	if(!newHashTable)
	{
		printf("[create_hashtable Function] Erreur Malloc newHashTable is NULL\n");
		return NULL;
	}
	newHashTable->size = size;
	newHashTable->tab = tab;



	//On remplit notre tableau avec nos clés
	while (tempHead)
	{
		//Dup la clé du citoyen
		Key* newKey = (Key*) malloc(sizeof(Key));
		if(!newKey)
		{
			printf("[create_hashtable Function] Erreur Malloc newKey is NULL\n");
			return NULL;
		}
		newKey->val = tempHead->data->val;
		newKey->n = tempHead->data->n;

		//New hash cell car 1 citoyen
		HashCell* hashCellCitoyen = create_hashcell(newKey);

		//Insértion dans le tableau
		int idx = find_position(newHashTable, newKey);

		//Si tab[idx] == NULL alors on le place sinon on le place a idx++ tant que idx n'est pas vide
		if (tab[idx] == NULL)
		{
			tab[idx] = hashCellCitoyen;
		} 
		else
		{
			while(tab[idx] != NULL)
			{
				//Si hors du tableau go back to 0
				if (idx >= (size-1))
				{
					idx = 0;
				}
				idx++;
			}

			tab[idx] = hashCellCitoyen;
		}

		tempHead = tempHead->next;
	}

	return newHashTable;
}

void print_hashtable(HashTable* t)
{
	for (int i = 0; i < t->size; i++)
	{
		if (t->tab[i])
		{
			printf("Cellule %d contient: %ld %ld\n", i, t->tab[i]->key->val, t->tab[i]->key->n);
		}
		else
		{
			printf("Cellule %d est NULL\n", i);
		}
	}
}

void delete_hashtable(HashTable* t)
{
	for (int i = 0; i < t->size; ++i)
	{
		if (t->tab[i])
		{
			delete_key(t->tab[i]->key);
			free(t->tab[i]);
		}
	}
	free(t->tab);
	free(t);
}

Key* compute_winner(CellProtected* decl, CellKey* candidates, CellKey* voters, int sizeC, int sizeV)
{
	//Table de Hachage des Candidats
	HashTable* hashTableCandidats = create_hashtable(candidates, sizeC*2);

	//Table de Hachage des Votants
	HashTable* hashTableVotants = create_hashtable(voters, sizeV*2);

	CellProtected* declTemp;

	//Parcours de toute la liste de déclaration
	for (declTemp = decl; declTemp; declTemp = declTemp->next) 
	{

		//Vérification de la signature
    	if (verify(declTemp->data) == 1)
    	{
    		//Vérification si la déclaration actuelle a déjà voté ou non
    		int citoyenIdx = find_position(hashTableVotants, declTemp->data->pKey);

    		//Candidat sélectioné par le citoyen to Key
    		Key* candidatKey = str_to_key(declTemp->data->mess);

    		int candidatIdx = find_position(hashTableCandidats, candidatKey);

    		//Vérification si la déclaration actuelle porte sur un candidat valide
    		if (hashTableCandidats->tab[candidatIdx] == NULL)
    		{
    			printf("Vote sur un candidat non déclaré\n");
    			continue;
    		}

    		if (hashTableVotants->tab[citoyenIdx] == NULL && hashTableVotants->tab[citoyenIdx]->val > 0)
    		{
    			printf("Citoyen idx a déjà voté: %d\n", citoyenIdx);
    			continue;
    		}

    		(hashTableVotants->tab[citoyenIdx]->val)++; //Update du votant a +1 car il vient de voté
    		(hashTableCandidats->tab[candidatIdx]->val)++; //Update du candidat +1 voie

    		delete_key(candidatKey);
    	}
    	else
    	{
    		printf("Signature invalide encore trouvé !\n");
    	}
  	}

  	//Recherche du gagnant de l'élection
  	int winnerIdx = 0;
  	int maxVoies = 0;
  	for (int i = 0; i < hashTableCandidats->size; ++i)
  	{
  		if (hashTableCandidats->tab[i] && hashTableCandidats->tab[i]->val > maxVoies)
  		{
  			maxVoies = hashTableCandidats->tab[i]->val;
  			winnerIdx = i;
  		}
  	}

  	Key* winnerKey = (Key*) malloc(sizeof(Key));
  	init_key(winnerKey, hashTableCandidats->tab[winnerIdx]->key->val, hashTableCandidats->tab[winnerIdx]->key->n);

  	char* winnerStr = key_to_str(winnerKey);
  	printf("Le winner est %s (%d Voies)\n", winnerStr, maxVoies);
  	delete_string(winnerStr);

  	delete_hashtable(hashTableCandidats);
  	delete_hashtable(hashTableVotants);

  	return winnerKey;
}
