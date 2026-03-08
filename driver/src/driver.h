#pragma once
#include <ntddk.h>
#include "process_list.h"

/* Pool tag — 'Sntl' in little-endian, used for any future pool allocations. */
#define SENTINEL_POOL_TAG 'ltnS'

/* Single global list of protected PIDs, defined in driver.c. */
extern PROTECTED_LIST g_ProtectedList;
