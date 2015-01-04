#define template_text "<$.%X>\r\n\
pushad\r\n\
call @f\r\n\
@@:\r\n\
pop ebp\r\n\
sub ebp, %X ; newentry+5-imagebase\r\n\
\r\n\
; Store imagebase\r\n\
call @f\r\n\
@getimagebase:\r\n\
mov ebp, 0FFFFFFFF\r\n\
ret\r\n\
@@:\r\n\
pop eax\r\n\
mov dword ptr ds:[eax+1],ebp\r\n\
\r\n\
; Get API addresses\r\n\
mov ebx, dword ptr ds:[ebp+%X] ; OutputDebugStringA\r\n\
lea esi, dword ptr ds:[ebp+%X] ; VirtualProtect\r\n\
\r\n\
; change page protection\r\n\
call @f\r\n\
\"\\x00\\x00\\x00\\x00\" ; oldprotect\r\n\
@@:\r\n\
push 40 ; newprotect\r\n\
push 50 ; size\r\n\
push ebx ; OutputDebugStringA\r\n\
call dword ptr ds:[esi] ; VirtualProtect\r\n\
\r\n\
; IAT Hook VirtualProtect\r\n\
call @vp_hook_end\r\n\
\r\n\
@hook_VirtualProtect:\r\n\
pushad\r\n\
pushfd\r\n\
call @getimagebase\r\n\
\r\n\
; restore IAT hook\r\n\
push esi\r\n\
push eax\r\n\
lea esi, dword ptr ds:[ebp+%X] ; VirtualProtect\r\n\
call @getvirtualprotect\r\n\
xchg dword ptr ds:[esi],eax\r\n\
pop eax\r\n\
pop esi\r\n\
\r\n\
; go to the user code\r\n\
jmp @usercode\r\n\
\r\n\
@vp_hook_end:\r\n\
pop ebp\r\n\
xchg dword ptr ds:[esi],ebp\r\n\
\r\n\
; store old VirtualProtect\r\n\
call @f\r\n\
@getvirtualprotect:\r\n\
mov eax,0FFFFFFFF\r\n\
ret\r\n\
@@:\r\n\
pop eax\r\n\
mov dword ptr ds:[eax+1],ebp\r\n\
\r\n\
; hook OutputDebugStringA\r\n\
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
\"\\x%02X\" ;counter\r\n\
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
\r\n\
; patch CRC values\r\n\
push eax\r\n\
%s\r\n\
pop eax\r\n\
\r\n\
jmp eax ; OutputDebugStringA\r\n\
\r\n\
; continue hooking OutputDebugStringA\r\n\
@od_hook_end:\r\n\
pop eax\r\n\
sub eax,5\r\n\
sub eax,esi\r\n\
mov dword ptr ds:[esi+1],eax\r\n\
\r\n\
; restore registers and jmp to oep\r\n\
popad\r\n\
jmp $.%X ;rva of oep\r\n\
\r\n\
@usercode:\r\n\
;PLACE YOUR CODE AFTER THIS (security base is in %s, imagebase in EBP)\r\n\
;PLACE YOUR CODE BEFORE THIS\r\n\
popfd\r\n\
popad\r\n\
call @getvirtualprotect\r\n\
jmp eax"
