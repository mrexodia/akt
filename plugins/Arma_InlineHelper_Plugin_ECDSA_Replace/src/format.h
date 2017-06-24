#define base_code_format "lea edi, dword ptr ds:[%s+0x%X]\r\n\
mov byte ptr ds:[edi],0xE9\r\n\
call @cert_replace_end\r\n\
%s\r\n\
@cert_replace_end:\r\n\
pop ebx\r\n\
sub ebx,edi\r\n\
lea ebx, dword ptr ds:[ebx-5]\r\n\
mov dword ptr ds:[edi+1],ebx\r\n\
lea edi, dword ptr ds:[%s+0x%X]\r\n\
mov word ptr ds:[edi],0xB890\r\n\
mov dword ptr ds:[edi+2],0x%s"

#define base_code_format2 "lea edi, dword ptr ds:[%s+0x%X]\r\n\
mov byte ptr ds:[edi],0xE9\r\n\
call @cert_replace_end\r\n\
%s\r\n\
@cert_replace_end:\r\n\
pop ebx\r\n\
sub ebx,edi\r\n\
lea ebx, dword ptr ds:[ebx-5]\r\n\
mov dword ptr ds:[edi+1],ebx\r\n"

#define repl_code_format2 "cmp dword ptr ds:[eax],0x%s\r\n\
je short @do_job\r\n\
ret\r\n\
@do_job:\r\n\
pushad\r\n\
lea edi,dword ptr ds:[eax+0x%s]\r\n\
call @f\r\n\
\"%s\\0\"\r\n\
@@:\r\n\
pop esi\r\n\
mov ecx,0x%X\r\n\
rep movsb\r\n\
popad\r\n\
ret"

#define repl_code_format "cmp dword ptr ds:[eax],0x%s\r\n\
je short @do_job\r\n\
ret\r\n\
@do_job:\r\n\
pushad\r\n\
mov byte ptr ds:[eax+0x%X],0x%s\r\n\
lea edi,dword ptr ds:[eax+0x%s]\r\n\
call @f\r\n\
\"%s\\0\"\r\n\
@@:\r\n\
pop esi\r\n\
mov ecx,0x%X\r\n\
rep movsb\r\n\
popad\r\n\
ret"
