#define template_text "\0<%08X>\r\n\
pushad\r\n\
mov ebx, dword ptr ds:[0%X] ; OutputDebugStringA\r\n\
mov edi, dword ptr ds:[0%X] ; VirtualProtect\r\n\
lea esi, dword ptr ds:[@oldprotect] ; oldprotect\r\n\
push esi\r\n\
push 40\r\n\
push 5\r\n\
push ebx ;OutputDebugString\r\n\
call edi ;VirtualProtect\r\n\
mov byte ptr ds:[ebx], 0E9\r\n\
lea eax, dword ptr ds:[@hook_OutputDebugStringA-5]\r\n\
sub eax, ebx\r\n\
mov dword ptr ds:[ebx+1], eax\r\n\
push esi\r\n\
push 40\r\n\
push 5\r\n\
push edi ;VirtualProtect\r\n\
call edi ;VirtualProtect\r\n\
mov byte ptr ds:[edi], 0E9\r\n\
lea eax, dword ptr ds:[@hook_VirtualProtect-5]\r\n\
sub eax, edi\r\n\
mov dword ptr ds:[edi+1], eax\r\n\
mov eax, @jmp_VirtualProtect\r\n\
sub edi, eax\r\n\
mov dword ptr ds:[@jmp_VirtualProtect+1], edi\r\n\
popad\r\n\
jmp 0%X ;OEP\r\n\
@oldprotect:\r\n\
\"\\0\\0\\0\\0\"\r\n\
@counter1:\r\n\
\"\\x%02X\\0\\0\\0\"\r\n\
@counter2:\r\n\
\"\\x01\"\r\n\
@hook_OutputDebugStringA:\r\n\
dec dword ptr ds:[@counter1]\r\n\
jnz short @not_done\r\n\
%s\r\n\
@not_done:\r\n\
xor eax,eax\r\n\
inc eax\r\n\
retn 4\r\n\
@hook_VirtualProtect:\r\n\
pushfd\r\n\
cmp byte ptr ds:[@counter2], 0\r\n\
je short @already_done\r\n\
dec byte ptr ds:[@counter2]\r\n\
pushad\r\n\
;PLACE YOUR CODE AFTER THIS (security base is in %s)\r\n\r\n\
;PLACE YOUR CODE BEFORE THIS\r\n\
popad\r\n\
@already_done:\r\n\
popfd\r\n\
push ebp\r\n\
mov ebp,esp\r\n\
@jmp_VirtualProtect:\r\n\
\"\\xE9\\0\\0\\0\\0\""

#define dll_template_text "\0<%08X>\r\n\
pushad\r\n\
mov ebx, dword ptr ds:[0%X] ; OutputDebugStringA\r\n\
mov esi, dword ptr ds:[0%X] ; VirtualProtect\r\n\
mov edi, dword ptr ds:[0%X] ; WriteProcessMemory\r\n\
lea ebp, dword ptr ds:[@write_bytes] ; write_bytes\r\n\
lea eax, dword ptr ds:[@hook_OutputDebugStringA-5]\r\n\
sub eax, ebx ; OutputDebugStringA\r\n\
mov dword ptr ds:[ebp+1], eax\r\n\
push 0\r\n\
push 5\r\n\
push ebp\r\n\
push ebx ; OutputDebugStringA\r\n\
push -1\r\n\
call edi ; WriteProcessMemory\r\n\
lea eax, dword ptr ds:[@hook_VirtualProtect-5]\r\n\
sub eax, esi ; VirtualProtect\r\n\
mov dword ptr ds:[ebp+1], eax\r\n\
push 0\r\n\
push 5\r\n\
push ebp\r\n\
push esi ; VirtualProtect\r\n\
push -1\r\n\
call edi ; WriteProcessMemory\r\n\
mov eax, @jmp_VirtualProtect\r\n\
sub esi, eax\r\n\
mov dword ptr ds:[@jmp_VirtualProtect+1], esi\r\n\
popad\r\n\
jmp 0%X ;OEP\r\n\
@write_bytes:\r\n\
\"\\xE9\\0\\0\\0\\0\\0\"\r\n\
@counter1:\r\n\
\"\\x%02X\\0\\0\\0\"\r\n\
@counter2:\r\n\
\"\\x01\"\r\n\
@hook_OutputDebugStringA:\r\n\
dec dword ptr ds:[@counter1]\r\n\
jnz short @not_done\r\n\
%s\r\n\
@not_done:\r\n\
xor eax,eax\r\n\
inc eax\r\n\
retn 4\r\n\
@hook_VirtualProtect:\r\n\
pushfd\r\n\
cmp byte ptr ds:[@counter2], 0\r\n\
je short @already_done\r\n\
dec byte ptr ds:[@counter2]\r\n\
pushad\r\n\
;PLACE YOUR CODE AFTER THIS (security base is in %s)\r\n\r\n\
;PLACE YOUR CODE BEFORE THIS\r\n\
popad\r\n\
@already_done:\r\n\
popfd\r\n\
push ebp\r\n\
mov ebp,esp\r\n\
@jmp_VirtualProtect:\r\n\
\"\\xE9\\0\\0\\0\\0\""
