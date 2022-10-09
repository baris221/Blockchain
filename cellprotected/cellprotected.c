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
#include "../cellprotected/cellprotectedH.h"



CellProtected* create_cell_protected(Protected* pr)
{
	CellProtected* newCellProtected = (CellProtected*) malloc(sizeof(CellProtected));
	if (!newCellProtected)
	{
		printf("[create_cell_protected Function] Erreur Malloc newCellProtected\n");
		return NULL;
	}

	newCellProtected->data = pr;
	newCellProtected->next = NULL;

	return newCellProtected;
}


void add_cell_protected(CellProtected** cellProtected, Protected* pr)
{
	if (!pr)    
        return;

    CellProtected *cp = create_cell_protected(pr);
    cp->next = *cellProtected;
    *cellProtected = cp;

	return;
}


CellProtected* read_protected(char* filename)
{
	FILE* file = fopen(filename, "r");
	if (!file)
	{
		printf("[read_protected Function] Erreur ouverture fichier: %s\n", filename);
		return NULL;
	}

	char buffer[256];

	CellProtected* cellProtected = NULL;

   while (fgets(buffer, 256, file))
   {
   	Protected* newProtected = str_to_protected(buffer);

   	if (!cellProtected)
   	{
   		cellProtected = create_cell_protected(newProtected);
   	} else {
   		add_cell_protected(&cellProtected, newProtected);
   	}
   }

   fclose(file);
   
	return cellProtected;
}

void print_list_protected(CellProtected* LP)
{
	if (!LP)
	{
		printf("[print_list_protected Function] Erreur LP NULL\n");
		return;
	}

	CellProtected* tmp;

	for (tmp = LP; tmp; tmp = tmp->next)
	{
		char* prStr = protected_to_str(tmp->data);
		printf("[Print CellProtected] Déclaration dans la liste chainée: %s\n", prStr);
		delete_string(prStr);
	}
}

void delete_cell_protected(CellProtected* cp)
{
	if (!cp)
	{
		printf("[delete_cell_protected Function] Erreur cp is NULL\n");
		return;
	}

	delete_protected(cp->data);
	free(cp);

	return;
}

void delete_list_protected(CellProtected* cellProtected)
{
	if (!cellProtected)
	{
		printf("[delete_list_protected Function] Erreur cellProtected NULL\n");
		return;
	}

	CellProtected* temp;

	while (cellProtected)
	{
		temp = cellProtected->next;
		
		delete_cell_protected(cellProtected);

		cellProtected = temp;
	}

	return;
}

//Supression des votes non valides
void verify_list_protected(CellProtected **LCP)  {
    if (!(*LCP))
    {
    	fprintf(stderr, "[verify_list_protected Function] *cellProtected => NULL\n");
        return;
    }

    CellProtected *first = *LCP;
    CellProtected *prev = first;
    CellProtected *curr = first->next;

    while (curr)    
    {
        if (!verify(curr->data))
        {
            prev->next = curr->next;

            //on supprime seulement la structure mais pas le contenu
            free(curr);    
        } else {
            prev = curr;
        }
        curr = prev->next;
    }

    if (!verify(first->data)) {
        *LCP = first->next;

        //on supprime seulement la structure mais pas le contenu
        free(first);
    }
}

CellProtected *fusionner_list_protected(CellProtected *votes1, CellProtected *votes2)
{
    //si une liste est vide, la fusion c'est l'autre
    if (!votes1)    {
        return votes2;
    }
    if (!votes2)    {
        return votes1;
    }
    //On parcourt votes1
    CellProtected *curr = votes1;
    while (curr->next)    {
        curr = curr->next;
    }
    curr->next = votes2;
    return votes1;
}

CellProtected *copie_list_protected(CellProtected *votes)
{
    if (!votes)
        return NULL;

    CellProtected *copie = NULL;
    while (votes)
    {
        add_cell_protected(&copie, votes->data);
        votes = votes->next;
    }
    return copie;
}