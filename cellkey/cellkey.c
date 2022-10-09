#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../rsa/rsaH.h"
#include "../primal/primalH.h"
#include "../key/keyH.h"
#include "../signature/signatureH.h"
#include "../protected/protectedH.h"
#include "../cellkey/cellkeyH.h"


CellKey* create_cell_key(Key* key)
{
	CellKey* newCellKey = (CellKey*) malloc(sizeof(CellKey));
	if (!newCellKey)
	{
		printf("[Create_Cell_Key Function] Erreur Malloc newCellKey\n");
		return NULL;
	}

	newCellKey->data = key;
	newCellKey->next = NULL;

	return newCellKey;
}

void add_cell_key(CellKey** cellKey, Key* key)
{
	if (!(*cellKey) || !key)
	{
		printf("[Add_Cell_Key Function] Erreur Key = NULL ou *newCellKey = NULL\n");
		return;
	}

	CellKey* newCellKey = create_cell_key(key);

	newCellKey->next = (*cellKey); 

	(*cellKey) = newCellKey;

	return;
}

CellKey* read_public_keys(char* filename)
{
	if (strcmp(filename, "candidates.txt") != 0 && strcmp(filename, "keys.txt") != 0)
	{
		printf("[Read_Public_Keys Function] Erreur fichier: %s invalide\n", filename);
		return NULL;
	}

	FILE* file = fopen(filename, "r");
	if (!file)
	{
		printf("[Read_Public_Keys Function] Erreur ouverture fichier: %s\n", filename);
		return NULL;
	}

	char buffer[256];
	long p,n;

	CellKey* cellKey = NULL;

   while (fgets(buffer, 256, file))
   {
   	sscanf(buffer, "(%lx,%lx)", &p, &n);

   	Key* publicKey = (Key*) malloc(sizeof(Key));
   	init_key(publicKey, p, n);

   	if (!cellKey)
   	{
   		cellKey = create_cell_key(publicKey);
   	} else {
   		add_cell_key(&cellKey, publicKey);
   	}
   }

   fclose(file);
   
	return cellKey;
}

void print_list_keys(CellKey* LCK)
{
	if (!LCK)
	{
		printf("[Print_List_Keys Function] Erreur LCK NULL\n");
		return;
	}

	CellKey* tmp;

	for (tmp = LCK; tmp; tmp = tmp->next)
	{
		char* keyStr = key_to_str(tmp->data);
		printf("[Print CellKeys] Clé publique dans la liste chainée: %s\n", keyStr);
		delete_string(keyStr);
	}
}

void delete_cell_key(CellKey* c)
{
	if (!c)
	{
		printf("[delete_cell_key Function] Erreur c is NULL\n");
		return;
	}

	delete_key(c->data);
	free(c);

	return;
}

void delete_list_keys(CellKey* cellKeys)
{
	if (!cellKeys)
	{
		printf("[delete_list_keys Function] Erreur cellKeys is NULL\n");
		return;
	}

	CellKey* temp;

	while (cellKeys)
	{
		temp = cellKeys->next;
		
		delete_cell_key(cellKeys);

		cellKeys = temp;
	}

	return;
}


int listKeyLength(CellKey *list)
{
   //Pour vérifier la longueur de la liste de cles
   //utilise dans compute_winner
   if (!list)  {
      return 0;
   }

   return 1 + listKeyLength(list->next);
}
