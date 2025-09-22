/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <windows.h>

#include "syscheck.h"
#include "registry/registry.h"
#include "registry/registry.c"

#include "../../wrappers/common.h"
#include "../../wrappers/windows/sddl_wrappers.h"
#include "../../wrappers/windows/aclapi_wrappers.h"
#include "../../wrappers/windows/winreg_wrappers.h"
#include "../../wrappers/windows/winbase_wrappers.h"
#include "../../wrappers/windows/securitybaseapi_wrappers.h"
#include "../../wrappers/wazuh/syscheckd/fim_db_wrappers.h"
#include "../../wrappers/wazuh/shared/syscheck_op_wrappers.h"
#include "../../wrappers/wazuh/syscheckd/fim_diff_changes_wrappers.h"
#include "../../wrappers/wazuh/shared/utf8_winapi_wrapper_wrappers.h"

#include "test_fim.h"

#define CHECK_REGISTRY_ALL                                                                             \
    CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_MD5SUM | CHECK_SHA1SUM | \
    CHECK_SHA256SUM | CHECK_SEECHANGES | CHECK_TYPE

extern int _base_line;

static registry_t default_config[] = {
    { "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL },
    { NULL, 0, 0, 320, 0, NULL, NULL, NULL }
};

static int setup_fim_read_values(void **state) {
    syscheck.registry = default_config;
    _base_line = 1; // Enable transaction callbacks
    return 0;
}

static int teardown_fim_read_values(void **state) {
    syscheck.registry = NULL;
    return 0;
}

// Test fim_read_values with ASCII value names
static void test_fim_read_values_ascii_value_names(void **state) {
    HKEY mock_key_handle = (HKEY)0x12345678;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 2;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 1024;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)0x87654321;
    fim_val_txn_context_t txn_ctx;
    event_data_t evt_data = {.mode = FIM_SCHEDULED, .type = FIM_ADD};
    txn_ctx.evt_data = &evt_data;

    // Mock value names and data
    wchar_t value1_name_w[] = L"TestValue1";
    wchar_t value2_name_w[] = L"TestValue2";
    DWORD value1_data = 12345;
    DWORD value2_data = 67890;

    // Mock wide_to_utf8 conversions
    expect_function_call(__wrap_wide_to_utf8);
    will_return(__wrap_wide_to_utf8, strdup("TestValue1"));
    expect_function_call(__wrap_wide_to_utf8);
    will_return(__wrap_wide_to_utf8, strdup("TestValue2"));

    // Mock first value enumeration
    expect_RegEnumValueW_call(value1_name_w, REG_DWORD, (LPBYTE)&value1_data, sizeof(DWORD), ERROR_SUCCESS);

    // Mock fim_check_restrict returning 0 (no restriction)
    expect_value(__wrap_fim_check_restrict, restriction, NULL);
    will_return(__wrap_fim_check_restrict, 0);

    // Mock fim_db_transaction_sync_row
    will_return(__wrap_fim_db_transaction_sync_row, 0);

    // Mock second value enumeration
    expect_RegEnumValueW_call(value2_name_w, REG_DWORD, (LPBYTE)&value2_data, sizeof(DWORD), ERROR_SUCCESS);

    expect_value(__wrap_fim_check_restrict, restriction, NULL);
    will_return(__wrap_fim_check_restrict, 0);

    will_return(__wrap_fim_db_transaction_sync_row, 0);

    // Mock third call returning error to end loop
    expect_RegEnumValueW_call(NULL, 0, NULL, 0, ERROR_NO_MORE_ITEMS);

    fim_read_values(mock_key_handle, path, arch, value_count, max_value_length, max_value_data_length, mock_txn_handler, &txn_ctx);
}

// Test fim_read_values with non-UTF8 (Unicode) value names
static void test_fim_read_values_unicode_value_names(void **state) {
    HKEY mock_key_handle = (HKEY)0x12345678;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 2;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 1024;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)0x87654321;
    fim_val_txn_context_t txn_ctx;
    event_data_t evt_data = {.mode = FIM_SCHEDULED, .type = FIM_ADD};
    txn_ctx.evt_data = &evt_data;

    // Mock Unicode value names containing non-ASCII characters
    wchar_t unicode_value1_w[] = L"测试值1"; // Chinese characters
    wchar_t unicode_value2_w[] = L"Tëst_Vâlüé2"; // Accented characters
    DWORD value1_data = 11111;
    DWORD value2_data = 22222;

    // Mock wide_to_utf8 conversions for Unicode strings
    expect_function_call(__wrap_wide_to_utf8);
    will_return(__wrap_wide_to_utf8, strdup("测试值1")); // UTF-8 encoded Chinese
    expect_function_call(__wrap_wide_to_utf8);
    will_return(__wrap_wide_to_utf8, strdup("Tëst_Vâlüé2")); // UTF-8 encoded accented chars

    // Mock first Unicode value enumeration
    expect_RegEnumValueW_call(unicode_value1_w, REG_DWORD, (LPBYTE)&value1_data, sizeof(DWORD), ERROR_SUCCESS);

    expect_value(__wrap_fim_check_restrict, restriction, NULL);
    will_return(__wrap_fim_check_restrict, 0);

    will_return(__wrap_fim_db_transaction_sync_row, 0);

    // Mock second Unicode value enumeration
    expect_RegEnumValueW_call(unicode_value2_w, REG_DWORD, (LPBYTE)&value2_data, sizeof(DWORD), ERROR_SUCCESS);

    expect_value(__wrap_fim_check_restrict, restriction, NULL);
    will_return(__wrap_fim_check_restrict, 0);

    will_return(__wrap_fim_db_transaction_sync_row, 0);

    // Mock third call returning error to end loop
    expect_RegEnumValueW_call(NULL, 0, NULL, 0, ERROR_NO_MORE_ITEMS);

    fim_read_values(mock_key_handle, path, arch, value_count, max_value_length, max_value_data_length, mock_txn_handler, &txn_ctx);
}

// Test fim_read_values when wide_to_utf8 returns NULL
static void test_fim_read_values_wide_to_utf8_null(void **state) {
    HKEY mock_key_handle = (HKEY)0x12345678;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 2;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 1024;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)0x87654321;
    fim_val_txn_context_t txn_ctx;
    event_data_t evt_data = {.mode = FIM_SCHEDULED, .type = FIM_ADD};
    txn_ctx.evt_data = &evt_data;

    wchar_t malformed_value_w[] = L"MalformedValue";
    wchar_t valid_value_w[] = L"ValidValue";
    DWORD malformed_data = 11111;
    DWORD valid_data = 22222;

    // Mock first value with wide_to_utf8 returning NULL (conversion failure)
    expect_function_call(__wrap_wide_to_utf8);
    will_return(__wrap_wide_to_utf8, NULL);

    expect_RegEnumValueW_call(malformed_value_w, REG_DWORD, (LPBYTE)&malformed_data, sizeof(DWORD), ERROR_SUCCESS);

    // Mock second value with successful conversion
    expect_function_call(__wrap_wide_to_utf8);
    will_return(__wrap_wide_to_utf8, strdup("ValidValue"));

    expect_RegEnumValueW_call(valid_value_w, REG_DWORD, (LPBYTE)&valid_data, sizeof(DWORD), ERROR_SUCCESS);

    expect_value(__wrap_fim_check_restrict, restriction, NULL);
    will_return(__wrap_fim_check_restrict, 0);

    will_return(__wrap_fim_db_transaction_sync_row, 0);

    // Mock third call returning error to end loop
    expect_RegEnumValueW_call(NULL, 0, NULL, 0, ERROR_NO_MORE_ITEMS);

    fim_read_values(mock_key_handle, path, arch, value_count, max_value_length, max_value_data_length, mock_txn_handler, &txn_ctx);
}

// Test fim_read_values with configuration validation failure
static void test_fim_read_values_null_configuration(void **state) {
    HKEY mock_key_handle = (HKEY)0x12345678;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\NonExistent\\Path";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 1024;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)0x87654321;
    fim_val_txn_context_t txn_ctx;
    event_data_t evt_data = {.mode = FIM_SCHEDULED, .type = FIM_ADD};
    txn_ctx.evt_data = &evt_data;

    // Mock configuration retrieval that returns NULL
    expect_any_always(__wrap__mdebug2, formatted_msg);

    fim_read_values(mock_key_handle, path, arch, value_count, max_value_length, max_value_data_length, mock_txn_handler, &txn_ctx);
}

// Test fim_read_values with various registry data types
static void test_fim_read_values_different_data_types(void **state) {
    HKEY mock_key_handle = (HKEY)0x12345678;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 4;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 1024;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)0x87654321;
    fim_val_txn_context_t txn_ctx;
    event_data_t evt_data = {.mode = FIM_SCHEDULED, .type = FIM_ADD};
    txn_ctx.evt_data = &evt_data;

    // Different data types
    wchar_t string_value_w[] = L"StringValue";
    wchar_t dword_value_w[] = L"DwordValue";
    wchar_t binary_value_w[] = L"BinaryValue";
    wchar_t multistring_value_w[] = L"MultiStringValue";

    char string_data[] = "Test string data";
    DWORD dword_data = 0x12345678;
    BYTE binary_data[] = {0x01, 0x02, 0x03, 0x04};
    char multistring_data[] = "String1\0String2\0String3\0\0";

    // Mock conversions for each value
    expect_function_call(__wrap_wide_to_utf8);
    will_return(__wrap_wide_to_utf8, strdup("StringValue"));
    expect_function_call(__wrap_wide_to_utf8);
    will_return(__wrap_wide_to_utf8, strdup("DwordValue"));
    expect_function_call(__wrap_wide_to_utf8);
    will_return(__wrap_wide_to_utf8, strdup("BinaryValue"));
    expect_function_call(__wrap_wide_to_utf8);  
    will_return(__wrap_wide_to_utf8, strdup("MultiStringValue"));

    // Mock REG_SZ value
    expect_RegEnumValueW_call(string_value_w, REG_SZ, (LPBYTE)string_data, strlen(string_data) + 1, ERROR_SUCCESS);
    expect_value(__wrap_fim_check_restrict, restriction, NULL);
    will_return(__wrap_fim_check_restrict, 0);
    will_return(__wrap_fim_db_transaction_sync_row, 0);

    // Mock REG_DWORD value  
    expect_RegEnumValueW_call(dword_value_w, REG_DWORD, (LPBYTE)&dword_data, sizeof(DWORD), ERROR_SUCCESS);
    expect_value(__wrap_fim_check_restrict, restriction, NULL);
    will_return(__wrap_fim_check_restrict, 0);
    will_return(__wrap_fim_db_transaction_sync_row, 0);

    // Mock REG_BINARY value
    expect_RegEnumValueW_call(binary_value_w, REG_BINARY, binary_data, sizeof(binary_data), ERROR_SUCCESS);
    expect_value(__wrap_fim_check_restrict, restriction, NULL);
    will_return(__wrap_fim_check_restrict, 0);
    will_return(__wrap_fim_db_transaction_sync_row, 0);

    // Mock REG_MULTI_SZ value
    expect_RegEnumValueW_call(multistring_value_w, REG_MULTI_SZ, (LPBYTE)multistring_data, sizeof(multistring_data), ERROR_SUCCESS);
    expect_value(__wrap_fim_check_restrict, restriction, NULL);
    will_return(__wrap_fim_check_restrict, 0);
    will_return(__wrap_fim_db_transaction_sync_row, 0);

    // End loop
    expect_RegEnumValueW_call(NULL, 0, NULL, 0, ERROR_NO_MORE_ITEMS);

    fim_read_values(mock_key_handle, path, arch, value_count, max_value_length, max_value_data_length, mock_txn_handler, &txn_ctx);
}

// Test fim_read_values with RegEnumValueW failure
static void test_fim_read_values_RegEnumValueW_failure(void **state) {
    HKEY mock_key_handle = (HKEY)0x12345678;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 1024;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)0x87654321;
    fim_val_txn_context_t txn_ctx;
    event_data_t evt_data = {.mode = FIM_SCHEDULED, .type = FIM_ADD};
    txn_ctx.evt_data = &evt_data;

    // Mock RegEnumValueW failure on first call
    expect_RegEnumValueW_call(NULL, 0, NULL, 0, ERROR_ACCESS_DENIED);

    fim_read_values(mock_key_handle, path, arch, value_count, max_value_length, max_value_data_length, mock_txn_handler, &txn_ctx);
}

// Test fim_read_values with restriction validation failure
static void test_fim_read_values_restrict_validation_failure(void **state) {
    HKEY mock_key_handle = (HKEY)0x12345678;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 1024;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)0x87654321;
    fim_val_txn_context_t txn_ctx;
    event_data_t evt_data = {.mode = FIM_SCHEDULED, .type = FIM_ADD};
    txn_ctx.evt_data = &evt_data;

    wchar_t restricted_value_w[] = L"RestrictedValue";
    DWORD value_data = 12345;

    expect_function_call(__wrap_wide_to_utf8);
    will_return(__wrap_wide_to_utf8, strdup("RestrictedValue"));

    expect_RegEnumValueW_call(restricted_value_w, REG_DWORD, (LPBYTE)&value_data, sizeof(DWORD), ERROR_SUCCESS);

    // Mock fim_check_restrict returning 1 (restricted)
    expect_value(__wrap_fim_check_restrict, restriction, NULL);
    will_return(__wrap_fim_check_restrict, 1);

    // End loop
    expect_RegEnumValueW_call(NULL, 0, NULL, 0, ERROR_NO_MORE_ITEMS);

    fim_read_values(mock_key_handle, path, arch, value_count, max_value_length, max_value_data_length, mock_txn_handler, &txn_ctx);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_fim_read_values_ascii_value_names, setup_fim_read_values, teardown_fim_read_values),
        cmocka_unit_test_setup_teardown(test_fim_read_values_unicode_value_names, setup_fim_read_values, teardown_fim_read_values),
        cmocka_unit_test_setup_teardown(test_fim_read_values_wide_to_utf8_null, setup_fim_read_values, teardown_fim_read_values),
        cmocka_unit_test_setup_teardown(test_fim_read_values_null_configuration, setup_fim_read_values, teardown_fim_read_values),
        cmocka_unit_test_setup_teardown(test_fim_read_values_different_data_types, setup_fim_read_values, teardown_fim_read_values),
        cmocka_unit_test_setup_teardown(test_fim_read_values_RegEnumValueW_failure, setup_fim_read_values, teardown_fim_read_values),
        cmocka_unit_test_setup_teardown(test_fim_read_values_restrict_validation_failure, setup_fim_read_values, teardown_fim_read_values),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}