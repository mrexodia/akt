<$%s.%X>
pushad
call @f
@@:
pop ebp
sub ebp,%X ;newentry+5-imagebase
;imagebase stuff
call @f
@getimagebase:
mov ebp,0FFFFFFFF
ret
@@:
pop eax
mov dword ptr ds:[eax+1],ebp
;imagebase stuff
mov ebx, dword ptr ds:[ebp+%X] ; OutputDebugStringA
mov esi, dword ptr ds:[ebp+%X] ; VirtualProtect

; Change page protection
call @f
\"\\x00\\x00\\x00\\x00\" ;oldprotect
@@:
push 40 ;newprotect
push 50 ;size
push esi ; VirtualProtect
call esi ; VirtualProtect
call @f
\"\\x00\\x00\\x00\\x00\" ;oldprotect
@@:
push 40 ;newprotect
push 50 ;size
push ebx ; OutputDebugStringA
call esi ; VirtualProtect

; Hook VirtualProtect
call @vp_skip
@vp_original_bytes:
call @f
\"\\x90\\x90\\x90\\x90\\x90\"
@@:
jmp short @vp_hook_back
@vp_skip:
pop edi
add edi,5
mov ecx,5
rep movs byte ptr es:[edi],byte ptr ds:[esi]
sub esi,5
mov byte ptr ds:[esi],0E9
call @vp_hook_end

@hook_VirtualProtect:
push edi
push esi
push ecx
push ebp
jmp short @vp_original_bytes
@vp_hook_back:
pop esi
call @getimagebase
mov eax,dword ptr ds:[ebp+%X] ; VirtualProtect
mov edi,eax
mov ecx,5
rep movs byte ptr es:[edi],byte ptr ds:[esi]
pop ebp
pop ecx
pop esi
pop edi

pushad
pushfd
;real hook here
%s
;real hook here
popfd
popad
jmp eax
@vp_hook_end:

pop eax
sub eax,5
sub eax,esi
mov dword ptr ds:[esi+1],eax
; Hook VirtualProtect

; Hook OutputDebugStringA
call @od_skip
@od_original_bytes:
call @f
\"\\x90\\x90\\x90\\x90\\x90\"
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
\"\\x02\" ;counter
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
push eax
%s
pop eax
jmp eax

@od_hook_end:
pop eax
sub eax,5
sub eax,esi
mov dword ptr ds:[esi+1],eax
; Hook OutputDebugStringA

popad
jmp $%s.%X ;rva of oep