#include "ce_detection.h"

std::vector<std::string>blacklisted_window_titles =
{
	"Cheat Engine",
	"Mugen JinFuu"
};

std::vector<std::string>blacklisted_process_names =
{
	"Cheat Engine",
	"cheatengine",
	"MugenJinFuu"
};

bool window_callback(HWND hwnd, LPARAM lparam) {

	std::vector<std::string>* titles = (std::vector<std::string>*)lparam;

	char window_title[2048];

	GetWindowTextA(hwnd, window_title, 2048);
	std::string title(&window_title[0]);
	if(title.length())
		titles->push_back(title);
}

std::vector<std::string>get_process_names() {
	std::vector<std::string> proc_names;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hsnap, &pe32)) {
		while (Process32Next(hsnap, &pe32)) {
			proc_names.push_back(pe32.szExeFile);
		}
	}
	CloseHandle(hsnap);
	return proc_names;
}

bool ce_detection::run_common() {
	bool detected = false;
	std::vector<std::string>titles;
	EnumWindows((WNDENUMPROC)window_callback, (LPARAM)&titles);

	for (auto title : titles)
	{
		for (auto blacklisted_title : blacklisted_window_titles) {
			if (title.find(blacklisted_title) != std::string::npos) {
				printf("Blacklisted window: %s\n", title.c_str());
				detected = true;
			}
		}
	}

	std::vector<std::string>proc_names = get_process_names();

	for (auto proc_name : proc_names) {
		for (auto blacklisted_process_name : blacklisted_process_names) {
			if (proc_name.find(blacklisted_process_name) != std::string::npos) {
				printf("Blacklisted process: %s\n", proc_name.c_str());
				detected = true;
			}
		}
	}
	return detected;
}

struct dbwin_buffer
{
	DWORD   dwProcessId;
	char    data[4096 - sizeof(DWORD)];
};

std::vector<std::string>blacklisted_debug_outputs =
{
	"Starting CE", //On startup
	"calling peinfo_getEntryPoint", //On new attach
	"calling peinfo_getdatabase", //On new attach
	"getProcessPathFromProcessID", //On new attach
	"TSavedScanHandler.InitializeScanHandler" //On memory scan
};

void ce_detection::run_advanced() {
	HANDLE hmutex = OpenMutexA(MUTEX_ALL_ACCESS, 0, "DBWinMutex");
	HANDLE hevent_buffer_ready = OpenEventA(EVENT_ALL_ACCESS, 0, "DBWIN_BUFFER_READY");
	if (hevent_buffer_ready == NULL) {
		hevent_buffer_ready = CreateEventA(NULL, FALSE, TRUE, "DBWIN_BUFFER_READY");
		if (!hevent_buffer_ready)
		{
			printf("Couldn't create DBWIN_BUFFER_READY!\n");
			return;
		}
	}

	HANDLE hevent_data_ready = OpenEventA(SYNCHRONIZE, 0, "DBWIN_DATA_READY");
	if (hevent_data_ready == NULL) {
		hevent_data_ready = CreateEventA(NULL, FALSE, FALSE, "DBWIN_DATA_READY");
		if (!hevent_data_ready)
		{
			printf("Couldn't create DBWIN_DATA_READY!\n");
			return;
		}
	}

	HANDLE file_mapping = OpenFileMappingA (FILE_MAP_READ, FALSE, "DBWIN_BUFFER");
	if (file_mapping == NULL) {
		file_mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(dbwin_buffer), "DBWIN_BUFFER");
		if (!file_mapping)
		{
			printf("Couldn't create DBWIN_BUFFER!\n");
			return;
		}
	}

	dbwin_buffer* buffer = (dbwin_buffer*)MapViewOfFile(file_mapping, SECTION_MAP_READ, 0, 0, 0);
	if (!buffer)
	{
		printf("Couldn't create buffer!\n");
		return;
	}
	while (true) {
		DWORD ret = WaitForSingleObject(hevent_data_ready, 1);

		if (ret == WAIT_OBJECT_0) {
			for (auto blacklisted_debug_output : blacklisted_debug_outputs) {
				if (std::string(buffer->data).find(blacklisted_debug_output) != std::string::npos) {
					printf("Blacklisted output: %s\n", buffer->data);
				}
			}
			SetEvent(hevent_buffer_ready);
		}
	}
}
