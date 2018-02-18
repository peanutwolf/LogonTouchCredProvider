#pragma once
#include <credentialprovider.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>

#define MAX_ULONG  ((ULONG)(-1))

enum TOUCH_FIELD_ID {
	TFI_LARGETEXT    = 0,
	TFI_SMALLTEXT    = 1,
	TFI_NUM_FIELDS   = 2,
};


struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

static const FIELD_STATE_PAIR s_rgTouchStatePairs[] =
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // TFI_LARGETEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },          // TFI_SMALLTEXT
};

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgTouchProvFieldDescriptors[] =
{
	{ TFI_LARGETEXT, CPFT_LARGE_TEXT, L"Username" },
	{ TFI_SMALLTEXT, CPFT_SMALL_TEXT, L"Info" },
};
