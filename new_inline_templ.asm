<$.%X>
pushad
call @f
@@:
pop ebp
sub ebp, %X ; newentry+5-imagebase

; Store imagebase
call @f
@getimagebase:
mov ebp, 0FFFFFFFF
ret
@@:
pop eax
mov dword ptr ds:[eax+1],ebp

; Get API addresses
mov ebx, dword ptr ds:[ebp+%X] ; OutputDebugStringA
lea esi, dword ptr ds:[ebp+%X] ; VirtualProtect

; change page protection
call @f
"\x00\x00\x00\x00" ; oldprotect
@@:
push 40 ; newprotect
push 50 ; size
push ebx ; OutputDebugStringA
call dword ptr ds:[esi] ; VirtualProtect

; IAT Hook VirtualProtect
call @vp_hook_end

@hook_VirtualProtect:
pushad
pushfd
call @getimagebase

; restore IAT hook
push esi
push eax
lea esi, dword ptr ds:[ebp+%X] ; VirtualProtect
call @getvirtualprotect
xchg dword ptr ds:[esi],eax
pop eax
pop esi

; go to the user code
jmp @usercode

@vp_hook_end:
pop ebp
xchg dword ptr ds:[esi],ebp

; store old VirtualProtect
call @f
@getvirtualprotect:
mov eax,0FFFFFFFF
ret
@@:
pop eax
mov dword ptr ds:[eax+1],ebp

; hook OutputDebugStringA
call @od_skip
@od_original_bytes:
call @f
"\x90\x90\x90\x90\x90"
@@:
jmp short @od_hook_back
@od_skip:
pop edi
add edi,5
mov esi,ebx
mov ecx,5
rep movs byte ptr es:[edi],byte ptr ds:[esi]
sub esi,5
mov byte ptr ds:[esi],0E9
call @od_hook_end

@hook_OutputDebugStringA:
call @f
"\x%02X" ;counter
@@:
pop eax
dec byte ptr ds:[eax]
jz short @od_execute_hook
xor eax,eax
inc eax
ret 4
@od_execute_hook:
push edi
push esi
push ecx
push ebp
jmp short @od_original_bytes
@od_hook_back:
pop esi
call @getimagebase
mov eax,dword ptr ds:[ebp+%X] ; OutputDebugStringA
mov edi,eax
mov ecx,5
rep movs byte ptr es:[edi],byte ptr ds:[esi]
pop ebp
pop ecx
pop esi
pop edi

; patch CRC values
push eax
%s
pop eax

jmp eax ; OutputDebugStringA

; continue hooking OutputDebugStringA
@od_hook_end:
pop eax
sub eax,5
sub eax,esi
mov dword ptr ds:[esi+1],eax

; restore registers and jmp to oep
popad
jmp $.%X ;rva of oep

@usercode:
;PLACE YOUR CODE AFTER THIS (security base is in %s, imagebase in EBP)
;PLACE YOUR CODE BEFORE THIS
popfd
popad
call @getvirtualprotect
jmp eax