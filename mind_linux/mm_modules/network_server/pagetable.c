#include "memory_management.h"

// x86_64, we assume no x86 PAE
static inline pgd_t *_pgd_alloc(void)
{
	return (pgd_t *)__get_free_pages(PGALLOC_GFP, PGD_ALLOCATION_ORDER);
}

static inline void _pgd_free(pgd_t *pgd)
{
	free_pages((unsigned long)pgd, PGD_ALLOCATION_ORDER);
}

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	pgd_t *pgd;
	pmd_t *pmds[PREALLOCATED_PMDS];

	pgd = _pgd_alloc();

	if (pgd == NULL)
		goto out;

	mm->pgd = pgd;

	if (preallocate_pmds(mm, pmds) != 0)
		goto out_free_pgd;

	if (paravirt_pgd_alloc(mm) != 0)
		goto out_free_pmds;

	/*
	 * Make sure that pre-populating the pmds is atomic with
	 * respect to anything walking the pgd_list, so that they
	 * never see a partially populated pgd.
	 */
	spin_lock(&pgd_lock);

	pgd_ctor(mm, pgd);
	pgd_prepopulate_pmd(mm, pgd, pmds);

	spin_unlock(&pgd_lock);

	return pgd;

out_free_pmds:
	free_pmds(mm, pmds);
out_free_pgd:
	_pgd_free(pgd);
out:
	return NULL;
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	pgd_mop_up_pmds(mm, pgd);
	pgd_dtor(pgd);
	paravirt_pgd_free(mm, pgd);
	_pgd_free(pgd);
}
