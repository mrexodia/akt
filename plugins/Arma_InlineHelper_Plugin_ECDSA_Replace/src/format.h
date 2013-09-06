#define base_code_format "lea edi, dword ptr ds:[%s+0%X]\r\n\
mov byte ptr ds:[edi],0E9\r\n\
call @cert_replace_end\r\n\
%s\r\n\
@cert_replace_end:\r\n\
pop ebx\r\n\
sub ebx,edi\r\n\
lea ebx, dword ptr ds:[ebx-5]\r\n\
mov dword ptr ds:[edi+1],ebx\r\n\
lea edi, dword ptr ds:[%s+0%X]\r\n\
mov word ptr ds:[edi],0B890\r\n\
mov dword ptr ds:[edi+2],0%s"

#define base_code_format2 "lea edi, dword ptr ds:[%s+0%X]\r\n\
mov byte ptr ds:[edi],0E9\r\n\
call @cert_replace_end\r\n\
%s\r\n\
@cert_replace_end:\r\n\
pop ebx\r\n\
sub ebx,edi\r\n\
lea ebx, dword ptr ds:[ebx-5]\r\n\
mov dword ptr ds:[edi+1],ebx\r\n"

#define repl_code_format2 "cmp dword ptr ds:[eax],0%s\r\n\
je short @do_job\r\n\
retn\r\n\
@do_job:\r\n\
pushad\r\n\
lea edi,dword ptr ds:[eax+0%s]\r\n\
call @f\r\n\
\"%s\\0\"\r\n\
@@:\r\n\
pop esi\r\n\
mov ecx,%X\r\n\
rep movs byte ptr es:[edi],byte ptr ds:[esi]\r\n\
popad\r\n\
retn"

#define repl_code_format "cmp dword ptr ds:[eax],0%s\r\n\
je short @do_job\r\n\
retn\r\n\
@do_job:\r\n\
pushad\r\n\
mov byte ptr ds:[eax+0%X],%s\r\n\
lea edi,dword ptr ds:[eax+0%s]\r\n\
call @f\r\n\
\"%s\\0\"\r\n\
@@:\r\n\
pop esi\r\n\
mov ecx,%X\r\n\
rep movs byte ptr es:[edi],byte ptr ds:[esi]\r\n\
popad\r\n\
retn"
