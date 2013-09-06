#define template_text "<$%s.%X>\r\n\
pushad\r\n\
call @f\r\n\
@@:\r\n\
pop ebp\r\n\
sub ebp,%X ;newentry+5-imagebase\r\n\
;imagebase stuff\r\n\
call @f\r\n\
@getimagebase:\r\n\
mov ebp,0FFFFFFFF\r\n\
ret\r\n\
@@:\r\n\
pop eax\r\n\
mov dword ptr ds:[eax+1],ebp\r\n\
;imagebase stuff\r\n\
mov ebx, dword ptr ds:[ebp+%X] ; OutputDebugStringA\r\n\
mov esi, dword ptr ds:[ebp+%X] ; VirtualProtect\r\n\
\r\n\
; Change page protection\r\n\
call @f\r\n\
\"\\x00\\x00\\x00\\x00\" ;oldprotect\r\n\
@@:\r\n\
push 40 ;newprotect\r\n\
push 50 ;size\r\n\
push esi ; VirtualProtect\r\n\
call esi ; VirtualProtect\r\n\
call @f\r\n\
\"\\x00\\x00\\x00\\x00\" ;oldprotect\r\n\
@@:\r\n\
push 40 ;newprotect\r\n\
push 50 ;size\r\n\
push ebx ; OutputDebugStringA\r\n\
call esi ; VirtualProtect\r\n\
\r\n\
; Hook VirtualProtect\r\n\
call @vp_skip\r\n\
@vp_original_bytes:\r\n\
call @f\r\n\
\"\\x90\\x90\\x90\\x90\\x90\"\r\n\
@@:\r\n\
jmp short @vp_hook_back\r\n\
@vp_skip:\r\n\
pop edi\r\n\
add edi,5\r\n\
mov ecx,5\r\n\
rep movs byte ptr es:[edi],byte ptr ds:[esi]\r\n\
sub esi,5\r\n\
mov byte ptr ds:[esi],0E9\r\n\
call @vp_hook_end\r\n\
\r\n\
@hook_VirtualProtect:\r\n\
push edi\r\n\
push esi\r\n\
push ecx\r\n\
push ebp\r\n\
jmp short @vp_original_bytes\r\n\
@vp_hook_back:\r\n\
pop esi\r\n\
call @getimagebase\r\n\
mov edi,dword ptr ds:[ebp+%X] ; VirtualProtect\r\n\
mov ecx,5\r\n\
rep movs byte ptr es:[edi],byte ptr ds:[esi]\r\n\
pop ebp\r\n\
pop ecx\r\n\
pop esi\r\n\
pop edi\r\n\
\r\n\
pushad\r\n\
pushfd\r\n\
call @getimagebase\r\n\
jmp @usercode\r\n\
@vp_hook_end:\r\n\
\r\n\
pop eax\r\n\
sub eax,5\r\n\
sub eax,esi\r\n\
mov dword ptr ds:[esi+1],eax\r\n\
; Hook VirtualProtect\r\n\
\r\n\
; Hook OutputDebugStringA\r\n\
call @od_skip\r\n\
@od_original_bytes:\r\n\
call @f\r\n\
\"\\x90\\x90\\x90\\x90\\x90\"\r\n\
@@:\r\n\
jmp short @od_hook_back\r\n\
@od_skip:\r\n\
pop edi\r\n\
add edi,5\r\n\
mov esi,ebx\r\n\
mov ecx,5\r\n\
rep movs byte ptr es:[edi],byte ptr ds:[esi]\r\n\
sub esi,5\r\n\
mov byte ptr ds:[esi],0E9\r\n\
call @od_hook_end\r\n\
\r\n\
@hook_OutputDebugStringA:\r\n\
call @f\r\n\
\"\\x02\" ;counter\r\n\
@@:\r\n\
pop eax\r\n\
dec byte ptr ds:[eax]\r\n\
jz short @od_execute_hook\r\n\
xor eax,eax\r\n\
inc eax\r\n\
ret 4\r\n\
@od_execute_hook:\r\n\
push edi\r\n\
push esi\r\n\
push ecx\r\n\
push ebp\r\n\
jmp short @od_original_bytes\r\n\
@od_hook_back:\r\n\
pop esi\r\n\
call @getimagebase\r\n\
mov eax,dword ptr ds:[ebp+%X] ; OutputDebugStringA\r\n\
mov edi,eax\r\n\
mov ecx,5\r\n\
rep movs byte ptr es:[edi],byte ptr ds:[esi]\r\n\
pop ebp\r\n\
pop ecx\r\n\
pop esi\r\n\
pop edi\r\n\
push eax\r\n\
%s\r\n\
pop eax\r\n\
jmp eax\r\n\
\r\n\
@od_hook_end:\r\n\
pop eax\r\n\
sub eax,5\r\n\
sub eax,esi\r\n\
mov dword ptr ds:[esi+1],eax\r\n\
; Hook OutputDebugStringA\r\n\
\r\n\
popad\r\n\
jmp $%s.%X ;rva of oep\r\n\
@usercode:\r\n\
;PLACE YOUR CODE AFTER THIS (security base is in %s, imagebase in EBP)\r\n\
;PLACE YOUR CODE BEFORE THIS\r\n\
popfd\r\n\
popad\r\n\
push ebp\r\n\
call @getimagebase\r\n\
mov eax, dword ptr ds:[ebp+%X] ; VirtualProtect\r\n\
pop ebp\r\n\
jmp eax"
