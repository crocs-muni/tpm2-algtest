#pragma once
#include "create.h"
#include <tss2/tss2_sys.h>

void test_CreatePrimary(TSS2_SYS_CONTEXT *sapi_context);
void prepare_create_primary_params(struct create_params *params,
        TPMA_OBJECT objectAttributes);
