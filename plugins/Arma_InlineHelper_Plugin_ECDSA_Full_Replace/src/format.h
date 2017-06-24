#define base_code_format "\0lea edi, dword ptr ds:[%s+0x%X]\r\n\
mov byte ptr ds:[edi],0xE9\r\n\
lea ebx, dword ptr es:[@cert_replace]\r\n\
sub ebx,edi\r\n\
lea ebx, dword ptr ds:[ebx-5]\r\n\
mov dword ptr ds:[edi+1],ebx\r\n\
lea edi, dword ptr ds:[%s+0x%X]\r\n\
mov word ptr ds:[edi],0xB890\r\n\
mov dword ptr ds:[edi+2],0x%s"

#define base_code_format2 "\0lea edi, dword ptr ds:[%s+0x%X]\r\n\
mov byte ptr ds:[edi],0xE9\r\n\
lea ebx, dword ptr es:[@cert_replace]\r\n\
sub ebx,edi\r\n\
lea ebx, dword ptr ds:[ebx-5]\r\n\
mov dword ptr ds:[edi+1],ebx\r\n"

#define repl_code_format "\0@cert_replace:\r\n\
cmp dword ptr ds:[eax],0x%s\r\n\
je @do_job\r\n\
ret\r\n\
@do_job:\r\n\
pushad\r\n\
lea edi,dword ptr ds:[eax+0x%s]\r\n\
lea esi,dword ptr ds:[@public]\r\n\
mov ecx,0x%X\r\n\
rep movsb\r\n\
popad\r\n\
ret\r\n\
@public:\r\n\
\"%s\\0\""

#define repl_code_format2 "\0@cert_replace:\r\n\
cmp dword ptr ds:[eax],0x%s\r\n\
je @do_job\r\n\
ret\r\n\
@do_job:\r\n\
pushad\r\n\
mov byte ptr ds:[eax+2],0x%s\r\n\
lea edi,dword ptr ds:[eax+0x%s]\r\n\
lea esi,dword ptr ds:[@public]\r\n\
mov ecx,0x%X\r\n\
rep movsb\r\n\
popad\r\n\
ret\r\n\
@public:\r\n\
\"%s\\0\""
