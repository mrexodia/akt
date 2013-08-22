#define base_code_format "\0lea edi, dword ptr ds:[%s+0%X]\r\n\
mov byte ptr ds:[edi],0E9\r\n\
lea ebx, dword ptr es:[@cert_replace]\r\n\
sub ebx,edi\r\n\
lea ebx, dword ptr ds:[ebx-5]\r\n\
mov dword ptr ds:[edi+1],ebx\r\n\
lea edi, dword ptr ds:[%s+0%X]\r\n\
mov word ptr ds:[edi],0B890\r\n\
mov dword ptr ds:[edi+2],0%s"

#define base_code_format2 "\0lea edi, dword ptr ds:[%s+0%X]\r\n\
mov byte ptr ds:[edi],0E9\r\n\
lea ebx, dword ptr es:[@cert_replace]\r\n\
sub ebx,edi\r\n\
lea ebx, dword ptr ds:[ebx-5]\r\n\
mov dword ptr ds:[edi+1],ebx\r\n"

#define repl_code_format "\0@cert_replace:\r\n\
cmp dword ptr ds:[eax],0%s\r\n\
je @do_job\r\n\
retn\r\n\
@do_job:\r\n\
pushad\r\n\
lea edi,dword ptr ds:[eax+0%s]\r\n\
lea esi,dword ptr ds:[@public]\r\n\
mov ecx,%X\r\n\
rep movs byte ptr es:[edi],byte ptr ds:[esi]\r\n\
popad\r\n\
retn\r\n\
@public:\r\n\
\"%s\\0\""

#define repl_code_format2 "\0@cert_replace:\r\n\
cmp dword ptr ds:[eax],0%s\r\n\
je @do_job\r\n\
retn\r\n\
@do_job:\r\n\
pushad\r\n\
mov byte ptr ds:[eax+0%X],%s\r\n\
lea edi,dword ptr ds:[eax+0%s]\r\n\
lea esi,dword ptr ds:[@public]\r\n\
mov ecx,%X\r\n\
rep movs byte ptr es:[edi],byte ptr ds:[esi]\r\n\
popad\r\n\
retn\r\n\
@public:\r\n\
\"%s\\0\""
