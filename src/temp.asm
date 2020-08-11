; ELF header.

BITS 32
            org     0x08048000

ehdr:                                                 ; Elf32_Ehdr
            db      0x7F, "ELF", 1, 1, 1, 0         ;   e_ident
    times 8 db      0
            dw      2                               ;   e_type
            dw      3                               ;   e_machine
            dd      1                               ;   e_version
            dd      _start                          ;   e_entry
            dd      phdr - $$                       ;   e_phoff
            dd      0                               ;   e_shoff
            dd      0                               ;   e_flags
            dw      ehdrsize                        ;   e_ehsize
            dw      phdrsize                        ;   e_phentsize
            dw      1                               ;   e_phnum
            dw      0                               ;   e_shentsize
            dw      0                               ;   e_shnum
            dw      0                               ;   e_shstrndx

ehdrsize      equ     $ - ehdr

phdr:                                                 ; Elf32_Phdr
            dd      1                               ;   p_type
            dd      0                               ;   p_offset
            dd      $$                              ;   p_vaddr
            dd      $$                              ;   p_paddr
            dd      filesize                        ;   p_filesz
            dd      filesize                        ;   p_memsz
            dd      5                               ;   p_flags
            dd      0x1000                          ;   p_align

phdrsize      equ     $ - phdr
ne803b9a29a204eff8c6b2da6b4b02756:
    dd      n76bba4a5b17940ee90d80c8f8893ca7d
    dd      n54b317ee93104ae3b7877a4f725296c6
    mov     byte [11947786], cl
    ret

n0a1d734cdbdd445284e466a5b10e0ce3:
    dd      n93698713774c402b87f6bf7b3690a2dd
    dd      nd3974848b2a84d8991b59df790e20567
    dec     bx
    ret

n44ca1f2c6f364a09a070f7d3d2018991:
    dd      n22cdbaa8a8c84e9b8e57d36122960bd1
    dd      n59bffc56972342478b322ec200f72e74
    mov     dword [58067359], ecx
    ret

ne0c2ce457b5a437e83c23b3480ca08c0:
    dd      n980009e26cf84291bb93eca3ca8be806
    dd      nbefde78b614341d8a18b3d2e00cd318e
    inc     ecx
    ret

ndb71519c622345a0b997f366a5a1d1d5:
    dd      nfeaeeef9ba3e4d9695082447c17b8e74
    dd      ne99671391f654a65a995470855fecd05
    cmp     edi, 60
    ret

nb26520eeac0e476585f023920cc2210f:
    dd      ne803b9a29a204eff8c6b2da6b4b02756
    dd      n532a7ba9fcd14ae5b590101e5357469a
    cmp     byte [112279766], ah
    ret

nfe8fdfbe7c574f79958a31102270ce4d:
    dd      nc4e9a20f15f6409a8e775a0196d26e80
    dd      nbf13ef9fb9844f86b19576141994b442
    mov     ecx, prompt
    ret

n9d5f73eb574549f9aead6d50853a92a5:
    dd      n3095ff3278b64557a17d1961c19a09ea
    dd      n7e564f0ebd16445195a65891ef22f6c5
    sub     dword [3596322], ebx
    ret

n3fb113cf9b864d948b1d5b2efc27a693:
    dd      nacce8e8728df46b494499e28c8c426bb
    dd      nee928b82cd3a4c66ad43b6d6951a9872
    dec     cx
    ret

n049023eb4ca14549a0478d228163a0c6:
    dd      n1cd3d63248174c529e65c182e05d4ebd
    dd      n14f738b864b640149d1fc8106b247666
    cmp     al, 124
    ret

n14be4e4bb7284845a29d0ce2d2d9d912:
    dd      n7490a6c6d79f4db7aaff71ab283ad629
    dd      nc57bed5bb9804337ad572d6aed59f5da
    sub     word [132572467], dx
    ret

n980009e26cf84291bb93eca3ca8be806:
    dd      n106bb5361957471fab96d942ced3954e
    dd      n0d6c9e09e1684adbb2e0f01a5e593c00
    cmp     byte [81745407], ch
    ret

n694a321ddf124add8d221d20bf0b3465:
    dd      ndc371b0c5f4a4fc88dffab8f61a9b730
    dd      n6c3799747d4046758bfb19d8d01258c8
    mov     al, byte [password+8]
    ret

n532a7ba9fcd14ae5b590101e5357469a:
    dd      nc3fb6d9341414899a962f08c6ad86613
    dd      n44ca1f2c6f364a09a070f7d3d2018991
    mov     word [53758390], si
    ret

n3f8d97f66ad64e46bc8c3c5c5f6464d8:
    dd      n1d55aa120bb44c8b859e33319dff93bf
    dd      ne6786640a13d42018a205f8ff4f5dc42
    add     dword [38332745], ecx
    ret

n8d85b96cea1447d38444ef5af62441da:
    dd      nfd4c80c91c524e83ba86a0f69c4c2657
    dd      ndc98ae68464f407eb2f3ca5f14383316
    inc     edx
    ret

nb2cb450ead9a4368bb496f673487a0d7:
    dd      nc186e74177e64b6b999ab06bd110641d
    dd      na0d3a7ed493842f385054886593fcfd8
    xor     al, byte [password+9]
    ret

n0c9d1aaa945c4609ad3768c996b01097:
    dd      n8bba225658f247a7be39346f282cec78
    dd      n9866f2c82e32499b98e2410c75833496
    add     ax, word [5217594]
    ret

nb62538f43b854d23988843fcdfe1f384:
    dd      na4a144a932ee430db4765fc978e119c7
    dd      nbf13ef9fb9844f86b19576141994b442
    mov     dh, 85
    ret

na7ddebfd7ba14f2f957c11411d7a0b5c:
    dd      nc8821a57aefb4505a7417b9ab23894ba
    dd      n2969a1c209354b0e9782709d2ea5b349
    add     ecx, 240
    ret

n8961c339142a4fbdb5818f4c6589136f:
    dd      n52381edf601d4c9588132bb9d089d3d0
    dd      nd974e7f33bda4ec5b5ebef3724a21e09
    xor     al, byte [password+1]
    ret

n8e830f95f71d4204bc6ea8e992ca546d:
    dd      n300c285ed94a47ec9cd12614ae2de3fd
    dd      n9f98ad0f7a1a4a0c8ad2f5d26b2543cb
    inc     ax
    ret

nf31c0b02ac3c4c19bbea0895b2216014:
    dd      na0815747fc284679892cb48887477fc1
    dd      nfbd345dd595245c89cb9c4515cd7b64b
    mov     eax, 3
    ret

nb310b0dc521e4a5cbfff1519a88c3636:
    dd      n3b53ddf0c21d448890519f79d9387913
    dd      n03ef5b48ae414027992ae823f77c0cff
    mov     dh, byte [120977195]
    ret

n768fedc792174092b44b8ee045a13627:
    dd      n9833ad5165a64011874aa22c4291eb18
    dd      n2e020de9c2ad41b193c6587afc39b40b
    cmp     ah, byte [103660338]
    ret

n7f11b9b233e14ee9a724a97e9b6095cb:
    dd      n2e31c92b141e41b0bbfa521d916eece2
    dd      nfdc994f17ced41e8982b4366249b785d
    cmp     al, 'C'
    ret

nbcdc253ea7534f158d056525d48924a4:
    dd      nd41f5ab8d9d946989dbe7b7fd489b582
    dd      n1e64eb2634ac4667b79882895e675339
    inc     esi
    ret

n6716398583314a56a2bcb01f1637d33e:
    dd      nc2ff2f03b0114af8a3f053024c707b53
    dd      n466522d5d73e4ff39cf2185020a38c0a
    dec     ch
    ret

ne7e315e057694739a8ce05238132a3f3:
    dd      n05d72dc1d1aa48258f927ac0651e510a
    dd      nbe1b39b536254d3095a0c469a4a21a61
    cmp     si, word [93451512]
    ret

n811ed6a98efb4cb49df075e763b02600:
    dd      ne85a7723726342109a861b342dd62b67
    dd      n06cb9599a24d4623a2120542f6fa0b48
    add     dword [94184168], edx
    ret

nec7891a2d33f44ef9d9067be0e79b515:
    dd      n5680725b0d544f37bd73883ef80c7454
    dd      neb8ace4946d746038f1130ffeff6864b
    add     ax, word [29287863]
    ret

n2b197406f91c4a98be6b961f67bf242a:
    dd      n4dfca2fd8320477e82566685570d1549
    dd      na6d1986cd8604b0485ba88916780d601
    sub     word [63956778], di
    ret

nb534c767d37c4efe990432585144eb64:
    dd      n1797b60b3b044ad987db2a34fb20bd75
    dd      nda5d3d732757443d9c5fdecbb07be84c
    inc     cl
    ret

na2c53f927d944691ae7233385fb8f410:
    dd      naf3d48576c214433860b4fbe2708b268
    dd      n045932780d624ca785de3aa609372f63
    inc     dx
    ret

nbe1487e18b8b47b5975d980a0e748d3a:
    dd      nb582d43b32b24e4baa337fb48afbe2ba
    dd      n4a99dcbaee334963b7f5b3e072f2bd4c
    cmp     dl, byte [77152440]
    ret

n1f44633b9e884a41aef9f6fa5e991ebf:
    dd      nd974e7f33bda4ec5b5ebef3724a21e09
    dd      nfd5ba5844c0848a888f033e524132cfe
    mov     byte [56476747], ch
    ret

nb49acae0567d455490aad378d7e29d97:
    dd      nb4d7c40b60e14e4ca4fe3b201df2bfee
    dd      n2209c5a15d084d7db92885414bab7791
    mov     bl, 0x76
    ret

nc452026c1f6a49bab3dbd76554f540b4:
    dd      n93698713774c402b87f6bf7b3690a2dd
    dd      n045932780d624ca785de3aa609372f63
    sub     ch, byte [71001097]
    ret

n231e2dbe260549c985d0377f1d863ea9:
    dd      n6b3a49dcb0c54c2ca67a2f596b2a040e
    dd      na367e6ebcd244100bcc900ff95ac3aa0
    mov     word [77663103], di
    ret

n8cfedf609e974442894a58da0abdcf52:
    dd      n51164a5f6ebb4963b0d2292561c929a4
    dd      nc5cd8ba1af8d4c54b7ecdcd79b8bf596
    jne     wrong
    ret

n34d6e76f705c48dfbd4a26a016c9d0be:
    dd      nddaf32feafd74be2a5429c8efc8e0ffb
    dd      n6e3b7aa03a9845f3b72a9ab1f6166aac
    dec     bx
    ret

n7e564f0ebd16445195a65891ef22f6c5:
    dd      nca39ac269f7e42f19f197375bc83ddcc
    dd      nbe1487e18b8b47b5975d980a0e748d3a
    cmp     bh, 226
    ret

nfd5ba5844c0848a888f033e524132cfe:
    dd      n0bdcecfad55b408899fb75e985d4a175
    dd      n0624375203a34924aab0af521605c94d
    mov     dl, byte [109455011]
    ret

n045932780d624ca785de3aa609372f63:
    dd      nfdc994f17ced41e8982b4366249b785d
    dd      n2b197406f91c4a98be6b961f67bf242a
    mov     dl, byte [9542400]
    ret

n30042a0a43fb425796e7f431368498ee:
    dd      n5af2a30b9c9c4d7797af2fd5fa6d4d1e
    dd      n049023eb4ca14549a0478d228163a0c6
    cmp     byte [38499555], bh
    ret

n292eb0cbb2154b8798e3f7ee9ad39913:
    dd      nbe1b39b536254d3095a0c469a4a21a61
    dd      n94f990aaa41848a890bff123a404ef29
    dec     bx
    ret

n54b317ee93104ae3b7877a4f725296c6:
    dd      n9fb8b51acfa64fc28f77e8bfd3ea3464
    dd      nc18db8e8188e470c8b00c00e981682de
    xor     al, 0xff
    ret

nbf13ef9fb9844f86b19576141994b442:
    dd      n5f9da57ddf104152afd5cc7d8af6353c
    dd      n85c22a9cfdb24dc383b9928ebe98464e
    mov     edi, 245
    ret

n2e7a463f43cd4b7eb0ae0b1d80b8105d:
    dd      ned54de41505a40059bf20e45bc9aff9c
    dd      na2c53f927d944691ae7233385fb8f410
    mov     al, byte [password+13]
    ret

n1cd3d63248174c529e65c182e05d4ebd:
    dd      na85e0595fcfe4b5286a281ee22b6559c
    dd      n1f455765812947c88170728a89594cae
    cmp     byte [29212960], ch
    ret

n6e3b7aa03a9845f3b72a9ab1f6166aac:
    dd      nff33a9e19452470f95e063004eb982b3
    dd      n8670f32eabd242aabfc51097b3bb73eb
    inc     ax
    ret

n0dc55db67785471aad7e4b55f775038a:
    dd      nc2c48b7e31a74a2dbe4db6fcdcbe0c3a
    dd      n3fb113cf9b864d948b1d5b2efc27a693
    jne     wrong
    ret

nd75fdccdd2794a1bafba5f50619af0db:
    dd      n9a8e9caceff44afca43e554b3db71fff
    dd      n597711df0d424df687d58e5533aba8e6
    inc     bl
    ret

nd3d1fb0b7dfb436186db40f976382d2a:
    dd      n6af3470de00b4eb196299c45c121249a
    dd      nf6e627d9ef63425b802e2649598dc8b9
    sub     eax, dword [73553645]
    ret

ne7852ddf93324e5cb675b3394a5dfc5f:
    dd      n012dd202b8124447b5f3106bcbdf6200
    dd      n77ae320a7dbf4447bca9976bad0666de
    inc     si
    ret

nfda1bf9b1122413fadf2c42e0094d105:
    dd      nfd4c80c91c524e83ba86a0f69c4c2657
    dd      na3eefeec12694b62b7bd1090cd22ee7f
    mov     word [49458110], ax
    ret

n005156cf71ba42428de4367e1fd43d94:
    dd      n50d8e9abacfa41f2bd8c73ce44ccbf53
    dd      nfb3d6071eeb846c897207f22a6cef0a7
    sub     edx, dword [75054406]
    ret

nf574803ad1124ff8af417be02e01651a:
    dd      n9bf16bc81d2a4b0996a332539b882285
    dd      na8309a29a7304d078d899b7898126dfd
    xor     al, byte [password+4]
    ret

nd292039494fe4560bc784a9d10e703b9:
    dd      n8755974bc5dd4c22aa4b2afa04bf3118
    dd      n08430aa944914df49f2244aba02bd86c
    add     ebx, 157
    ret

n2713aca90bed4e96ba36e770da8aeff7:
    dd      na0815747fc284679892cb48887477fc1
    dd      nd896a85d040544d5ab6d057fff5e342d
    mov     word [120184023], bx
    ret

n0dd1a486038a45728ba0ef206705d654:
    dd      nf4e75c89173647c78469fdc93c5085a4
    dd      nf4cc94a4b239462f8ff7199a2981a736
    mov     al, byte [password+14]
    ret

n9f98ad0f7a1a4a0c8ad2f5d26b2543cb:
    dd      n85930114cb17467a87fddb779d87ad10
    dd      nfbd345dd595245c89cb9c4515cd7b64b
    mov     dword [80340137], eax
    ret

n36d0639643b24eadb849bad70068ed15:
    dd      n4c2edad7a4494421a16e6a7e6a839459
    dd      n3b12a61cc0a44a8a8c7942921b41e1fb
    sub     word [25692463], cx
    ret

na0d3a7ed493842f385054886593fcfd8:
    dd      n64332f29ce51490a9ebc01255027d374
    dd      n36e9ac04f5614625ae5626d9288d5ee5
    xor     al, byte [password+8]
    ret

n0352ee27c2ee47819b00d5b3a4615bdd:
    dd      n300c285ed94a47ec9cd12614ae2de3fd
    dd      nc57bed5bb9804337ad572d6aed59f5da
    dec     edx
    ret

n39a5b81fb07e48999cc7ec94e692fff2:
    dd      n597711df0d424df687d58e5533aba8e6
    dd      n84692e4e68724ac4a3b1e8f555bcb444
    sub     eax, 67
    ret

nfeec65e0644648bd94aa284030a729fb:
    dd      n9fa9353c97574f55ad03624c99cd445c
    dd      n2713aca90bed4e96ba36e770da8aeff7
    inc     ah
    ret

nb2afbd1804d146bcbedbc96ce40e9d8f:
    dd      n0352ee27c2ee47819b00d5b3a4615bdd
    dd      n527f09a0a4394d09ac26efba580431ac
    sub     ecx, dword [33138436]
    ret

nb64eec799e274ba0858474d679ff733d:
    dd      n9a8e9caceff44afca43e554b3db71fff
    dd      n5e82d9b9a55d4e1987919e1462ac1080
    inc     ax
    ret

n2e020de9c2ad41b193c6587afc39b40b:
    dd      n9a8e9caceff44afca43e554b3db71fff
    dd      n4a99dcbaee334963b7f5b3e072f2bd4c
    cmp     si, word [22706871]
    ret

nfbd345dd595245c89cb9c4515cd7b64b:
    dd      na86c58288c4b4e2faafc7a84474dd8ff
    dd      n0b0e639acb7e43f3a6b47a38207bf9e7
    mov     ebx, 0
    ret

n4b3f95fe70644aff960f49861088391e:
    dd      nf7698fe0e9e349d8ada5aad4c737ab5d
    dd      n5e82d9b9a55d4e1987919e1462ac1080
    mov     ecx, 222
    ret

nb7553349f2454559ac3aa224d5e2e86c:
    dd      n34d6e76f705c48dfbd4a26a016c9d0be
    dd      nd4ce7ad1d78e4682b0b641331da0a6ca
    cmp     al, al
    ret

n5af4f220065a42f98ee07aa63dcc7b90:
    dd      n11840b18effb4282ba1fe11abe59ba18
    dd      na81735aebec240b6867724ddde765169
    sub     esi, dword [46266362]
    ret

ne2c3553cb74a47dfb24949afacd9b21f:
    dd      n064722e97de14fb58b79989a18573e10
    dd      nb64eec799e274ba0858474d679ff733d
    add     bh, byte [33603961]
    ret

n65bc5c9678e848eb895175b52eaa2782:
    dd      n5b520798b98f43e3af07313297b1da14
    dd      nea549e8f387a4766bfd9953187061c1e
    sub     di, 176
    ret

n1a18a9386ba844f397c63c2b3e22b865:
    dd      n8bba225658f247a7be39346f282cec78
    dd      n3b53ddf0c21d448890519f79d9387913
    cmp     dword [94270282], ecx
    ret

n4a78061052ca4bfd9c6f1ced7805659d:
    dd      nc96723d13d7b483ca45c9592e968da63
    dd      neeca4ee0e64f41f08ec0f13ffb7a1b76
    xor     bl, byte [password+6]
    ret

ne85a7723726342109a861b342dd62b67:
    dd      nb8e714736cc7478eaf0d66bd45db5be8
    dd      n19043426c5ea48fb9719f43c22b0c9ee
    mov     al, byte [password+9]
    ret

nb3a76f134d9649e780c57f54fa82b469:
    dd      n4750902797504585be24b2e3dc2f8736
    dd      nb8acb7da1297410bacc2ccaef3adb2c3
    cmp     esi, 20
    ret

nce69d096231d45989160e5f54570ead0:
    dd      n3bdbd8950451478895c49391b75a2420
    dd      nc20299d80e0a46bb91b3c188282c4053
    add     eax, dword [10769444]
    ret

nc20299d80e0a46bb91b3c188282c4053:
    dd      nb3425231937741e88bac48027690bec7
    dd      nff33a9e19452470f95e063004eb982b3
    dec     ch
    ret

n665b80eefd7342faa665b5848669393f:
    dd      n1cd3d63248174c529e65c182e05d4ebd
    dd      nadd9bbb9a2cd476d98d4e424e9c47c55
    dec     dh
    ret

nf420c1a059b5498cbdff555595c6576f:
    dd      n5af4f220065a42f98ee07aa63dcc7b90
    dd      n6174e0f3a44949baa47d2f8c24e24f20
    add     dh, 140
    ret

n2ac793d5528d4a5486fdbd244fe6e56a:
    dd      nb7553349f2454559ac3aa224d5e2e86c
    dd      nf574803ad1124ff8af417be02e01651a
    mov     dword [133663157], esi
    ret

n4712713825bd4d7996f96eb440ccd42b:
    dd      nafd3c3e0b1f74b82bcc1d0a25f8915ac
    dd      n694a321ddf124add8d221d20bf0b3465
    add     byte [52506653], ah
    ret

n56bc96cb21e84eaead5b189376ec853f:
    dd      nbcdc253ea7534f158d056525d48924a4
    dd      n2d034e0326254dec9962b5cf88076b3f
    inc     cl
    ret

nd6745450848e439fb99bdf86ec7575a0:
    dd      n597711df0d424df687d58e5533aba8e6
    dd      n683c40c8e54b471ea460f7db225b0546
    mov     si, word [133915468]
    ret

nf1aeb5633135417eb54a140756ed33fa:
    dd      nef5717b316d54c0ca6b8d4fd90c35a02
    dd      nb2cb450ead9a4368bb496f673487a0d7
    xor     al, byte [password+10]
    ret

n753dbca0445a438d916286833fa4436c:
    dd      nd3d1fb0b7dfb436186db40f976382d2a
    dd      n8670f32eabd242aabfc51097b3bb73eb
    sub     dword [85551307], eax
    ret

n2bf3174c21fd4cf2aff3dddf9be08f9f:
    dd      na9a654ffa33447c995eceae05369bd90
    dd      n00616bea27464bb393cb0bb001a81dfe
    inc     esi
    ret

na2df715b7f3846ebbd59e736b767be08:
    dd      nafd3c3e0b1f74b82bcc1d0a25f8915ac
    dd      ne803b9a29a204eff8c6b2da6b4b02756
    dec     dl
    ret

nd4ce7ad1d78e4682b0b641331da0a6ca:
    dd      nffe7c0690c3e400a9dee8b27613b7aed
    dd      nb7e2ec18e52e4bb2b63b16fd868c6523
    jnz     wrong
    ret

n9b4434d551ff46aa8a10d689d3cfe93e:
    dd      n2b13f77ecea346c5ad19d65386f49f91
    dd      n527f09a0a4394d09ac26efba580431ac
    int     0x80
    ret

n03febc0048e3402ba36b4100f397d40e:
    dd      n14be4e4bb7284845a29d0ce2d2d9d912
    dd      n1b72b07c60dc4a5d99034bd8fea16e54
    cmp     dword [4805842], ecx
    ret

n48154172937f411b8964c9ee9dcc546a:
    dd      nb582d43b32b24e4baa337fb48afbe2ba
    dd      n106bb5361957471fab96d942ced3954e
    dec     dh
    ret

n00fa8e64b3f14195a740ab08b1a0f30f:
    dd      n03febc0048e3402ba36b4100f397d40e
    dd      nd584ec595c604418b5e8cb1e77890931
    mov     bh, 128
    ret

n9dab7aff955b46e09e283e3cd4125a10:
    dd      n06cb9599a24d4623a2120542f6fa0b48
    dd      naf3d48576c214433860b4fbe2708b268
    inc     bh
    ret

n51164a5f6ebb4963b0d2292561c929a4:
    dd      nc3fb6d9341414899a962f08c6ad86613
    dd      nfda1bf9b1122413fadf2c42e0094d105
    dec     ah
    ret

na726c4fe15f440b8ad7e7c1af5780d04:
    dd      n3095ff3278b64557a17d1961c19a09ea
    dd      n93698713774c402b87f6bf7b3690a2dd
    inc     esi
    ret

n3bdbd8950451478895c49391b75a2420:
    dd      n3095ff3278b64557a17d1961c19a09ea
    dd      n969cc93adfc04fbc8646689ccbca4227
    inc     ax
    ret

nd0e88f10eb4d49ffa98d1e0da6b7ef63:
    dd      nddd040df65064f9f9e7ad5687601624f
    dd      n064722e97de14fb58b79989a18573e10
    cmp     al, al
    ret

n4ea0c1362ca5448193daeead0d04b9fb:
    dd      n6e7e9901298842daaf2c566a1d878466
    dd      n9dab7aff955b46e09e283e3cd4125a10
    dec     bx
    ret

nd9b5c40a883847ca89becaf84d37a48f:
    dd      n7f11b9b233e14ee9a724a97e9b6095cb
    dd      n4a78061052ca4bfd9c6f1ced7805659d
    sub     edi, dword [54148920]
    ret

n9a8e9caceff44afca43e554b3db71fff:
    dd      nc186e74177e64b6b999ab06bd110641d
    dd      ndaddf96096c1447ca11fc034148735ba
    add     word [60737531], bx
    ret

n90c6a7e3761144b58efeb93c2708a573:
    dd      n7f11b9b233e14ee9a724a97e9b6095cb
    dd      n183702569a8c4b9ca9e70a11841c5207
    mov     al, byte [password]
    ret

n48e6d5facdc34c8885bfbbf0fb9a0a49:
    dd      nd974e7f33bda4ec5b5ebef3724a21e09
    dd      n633e47ce3bc84cbdb7be4aef2b86a4ff
    sub     ax, 208
    ret

nb65327ad1e834f70ad788539f94c9c34:
    dd      n916264c9c532434bb584774c3abd0091
    dd      n05d72dc1d1aa48258f927ac0651e510a
    add     edi, dword [109076385]
    ret

n73f074b682f144189130234cb394d68d:
    dd      n6c3799747d4046758bfb19d8d01258c8
    dd      nc20299d80e0a46bb91b3c188282c4053
    sub     ch, byte [130861089]
    ret

n9c39cfd1ae074758bfd9ce71512ca022:
    dd      n51a41bd3cfc04df8909260bf6583a678
    dd      nf49716b112d64a8d9fb69476de8c7bca
    jne     wrong
    ret

n2db441abebdc450386cb7ec4745f270a:
    dd      n90c6a7e3761144b58efeb93c2708a573
    dd      n429cad16f40644d1b1ad3ad713b16e6e
    mov     edx, 0
    ret

n5daddf94668541d3ae8c1061a91851f8:
    dd      nd0e4d1612d29459ba6d877eae9bc34f6
    dd      nc18db8e8188e470c8b00c00e981682de
    add     word [79767103], cx
    ret

na81735aebec240b6867724ddde765169:
    dd      ned7202b2825d4ebc9814b22d2cd9d932
    dd      n8179f5a0fe6d4c6dac74ef378fb98991
    cmp     al, 0x42
    ret

n22cdbaa8a8c84e9b8e57d36122960bd1:
    dd      nd4b368a41e6a4dacb3ec3ffd85b4c4a4
    dd      ndda70f3f37f14b4b8a18eb222be6ccf8
    add     di, 232
    ret

n7ac1cb482f984e65980125dd926327cc:
    dd      nd7baf9cb766949d1a4a79d5b148df0e5
    dd      nfda1bf9b1122413fadf2c42e0094d105
    inc     edx
    ret

nd16078537eb44433ba0f8ab7648d3c3d:
    dd      n13ffafc1c45f49e9862a41037148e5a7
    dd      n6716398583314a56a2bcb01f1637d33e
    mov     dh, byte [77996858]
    ret

na846af1c232748ba9529a6edd93ad359:
    dd      nbbd8c9eca97b44b3b5170caed6b3b370
    dd      n118bc3fd95ee479a9c378c4581e0a24e
    sub     ecx, dword [97812231]
    ret

n0624375203a34924aab0af521605c94d:
    dd      n7271295e9a134c1f87e570d9c5d523e3
    dd      n44ca1f2c6f364a09a070f7d3d2018991
    inc     al
    ret

neb8ace4946d746038f1130ffeff6864b:
    dd      n38fb10a412ed439ba7c8f722e54d4646
    dd      nfb3d6071eeb846c897207f22a6cef0a7
    dec     edx
    ret

n85930114cb17467a87fddb779d87ad10:
    dd      n48f512b07ed741429d4417dfdea79b9b
    dd      nf1aeb5633135417eb54a140756ed33fa
    xor     al, byte [password+11]
    ret

n5f9da57ddf104152afd5cc7d8af6353c:
    dd      n969cc93adfc04fbc8646689ccbca4227
    dd      nbcdc253ea7534f158d056525d48924a4
    add     byte [108962915], al
    ret

n125215488dc24b50b95b9f9f3f82409d:
    dd      n7a034e59451a47dabc3a9118adb3161a
    dd      n30042a0a43fb425796e7f431368498ee
    add     esi, 204
    ret

nbc5d138188e84abd9ed8681eb52bcc54:
    dd      na890ca84908c479bb53b29ee50a8d4e6
    dd      n52ae5a262d1041288ccf9a05b03a5ebe
    dec     al
    ret

nc3d704a127084de893121451b121fc40:
    dd      n99f24fa864ee40f68254432c94a48c3e
    dd      n3d11fd72da04432fbd60b415a96824a6
    sub     dword [66576409], edx
    ret

n9bf16bc81d2a4b0996a332539b882285:
    dd      nd41f5ab8d9d946989dbe7b7fd489b582
    dd      nec7891a2d33f44ef9d9067be0e79b515
    dec     cx
    ret

n864cc51eff834bb0be61afcd15d66fa5:
    dd      n621e3fbc6fb34509a61f1e40390ac910
    dd      n7ef0248b25ac444fadded4e5672784e9
    int     0x80
    ret

n9866f2c82e32499b98e2410c75833496:
    dd      n7f11b9b233e14ee9a724a97e9b6095cb
    dd      nbf13ef9fb9844f86b19576141994b442
    sub     esi, dword [94653206]
    ret

n10c262302cc848b1a09ed67d0442a523:
    dd      n6716398583314a56a2bcb01f1637d33e
    dd      n4b3f95fe70644aff960f49861088391e
    cmp     ecx, dword [90664624]
    ret

nb50de4853455434b8ba9d6017fd2ee7d:
    dd      nd16078537eb44433ba0f8ab7648d3c3d
    dd      n878a77636b344c77b3c5824ae17bcb95
    dec     cx
    ret

n4086554cd5c849afa03e7c887e10b1df:
    dd      n4a3c18da62b9466ea037138ab61d05ef
    dd      n466522d5d73e4ff39cf2185020a38c0a
    cmp     word [58915670], bx
    ret

n864518d5da21446bb4488208e2a4c414:
    dd      n675acff081f54b89920fbcb96e7d0209
    dd      nba025563875b48d7b86671ab4f856f01
    inc     ch
    ret

n5d9bd9a935984ebb8ea1ccfbf71dcf26:
    dd      n818a89cb7d8a4bfa917cfca7efa7c9a0
    dd      n3bda26cdb1834182b6720e99550d1787
    sub     cx, 8
    ret

nbb43ec945203475b8e8cec8252004a6c:
    dd      n50c35b6396794f369584b4b2c03a2412
    dd      n30042a0a43fb425796e7f431368498ee
    dec     edi
    ret

n77193e3e51cd472f864d456f707184cd:
    dd      start
    dd      nb78350ff87cf40378f7155704443b2d7
    cmp     dword [113323009], edi
    ret

ne88d31955f4c4767ad636a679e1aa50e:
    dd      n3bdbd8950451478895c49391b75a2420
    dd      nb78350ff87cf40378f7155704443b2d7
    mov     ebx, 1
    ret

n736e82eda84d4e28879da0add5ba241c:
    dd      n5e82d9b9a55d4e1987919e1462ac1080
    dd      na7ddebfd7ba14f2f957c11411d7a0b5c
    mov     dl, byte [46069607]
    ret

ne28ce39ac8554c14a689cc85f23bb0f4:
    dd      n736e82eda84d4e28879da0add5ba241c
    dd      n4712713825bd4d7996f96eb440ccd42b
    sub     dword [122291736], esi
    ret

nb8302ef780404cf1afa9254472dfd7d1:
    dd      n48f512b07ed741429d4417dfdea79b9b
    dd      n4ea0c1362ca5448193daeead0d04b9fb
    inc     eax
    ret

n4cde16b6cd544de98795772b18b6b481:
    dd      n9351c0dce0244920b29057970f4a9674
    dd      n6e3b7aa03a9845f3b72a9ab1f6166aac
    sub     dl, 155
    ret

n932699cc74fa486ebdb6f7495187dfb7:
    dd      nf4cc94a4b239462f8ff7199a2981a736
    dd      nd41f5ab8d9d946989dbe7b7fd489b582
    add     eax, dword [78108403]
    ret

nd41f5ab8d9d946989dbe7b7fd489b582:
    dd      n64332f29ce51490a9ebc01255027d374
    dd      nb26520eeac0e476585f023920cc2210f
    mov     dword [38709881], esi
    ret

nbd416d5fdc124497b7b87193f9109893:
    dd      n8d85b96cea1447d38444ef5af62441da
    dd      nbda30450f16d4d428905360da1078329
    add     cl, byte [21162625]
    ret

ne8d63aae50b1412b95e5f5d1af4b95b4:
    dd      n2b197406f91c4a98be6b961f67bf242a
    dd      n633e47ce3bc84cbdb7be4aef2b86a4ff
    dec     edx
    ret

n4d37767f119a415ea7ab685d4f219b0d:
    dd      n5f9da57ddf104152afd5cc7d8af6353c
    dd      n84692e4e68724ac4a3b1e8f555bcb444
    sub     ebx, 215
    ret

nf45e9ed78f98441aa762e74883d8eb66:
    dd      n8670f32eabd242aabfc51097b3bb73eb
    dd      nb4028fa20e974454a9b038e0abf52c87
    mov     cx, word [45645]
    ret

n880635899a114bf1b7bae4af840d68ac:
    dd      neb86cf7ba6904475a079765580056f4c
    dd      n9c44a1baa2634057855b9845928063d9
    dec     esi
    ret

n1a2f998edd8a4d09b274f4154b1ca21d:
    dd      n6cf93a5a3aae44b1acec7c9cb5b8ebcd
    dd      n6e3b7aa03a9845f3b72a9ab1f6166aac
    mov     al, byte [84322381]
    ret

n52381edf601d4c9588132bb9d089d3d0:
    dd      na2df715b7f3846ebbd59e736b767be08
    dd      n5af2a30b9c9c4d7797af2fd5fa6d4d1e
    xor     al, byte [password]
    ret

n63e4dff5950349d589859194b113b2dc:
    dd      nbbd8c9eca97b44b3b5170caed6b3b370
    dd      n8ab7ade040014c39a0f87ef975938392
    dec     cx
    ret

nd4b368a41e6a4dacb3ec3ffd85b4c4a4:
    dd      n88e29c0e7370476cb68dedbc7ea3d4c2
    dd      n89a7a87978274ce4bb01bedf95ec20b7
    add     word [110969572], dx
    ret

nd97ea5ef0f03412799b99b78890010e5:
    dd      nb544503268df4b19a140a7e4e07af025
    dd      n7e8326cd5f134546b9b5b664f4d25e5d
    jnz     wrong
    ret

n106bb5361957471fab96d942ced3954e:
    dd      n23ffb80afc7240fcaec9263bec31019e
    dd      n84692e4e68724ac4a3b1e8f555bcb444
    add     word [120216918], ax
    ret

n9e9aa29a1d0247e0ac02f8153e22ad1c:
    dd      nf3535c22d8164bdc9260d26d955b1bca
    dd      n665b80eefd7342faa665b5848669393f
    sub     cx, 169
    ret

ncbf85b0b9ca64479a4232f2cbf28f96e:
    dd      nacce8e8728df46b494499e28c8c426bb
    dd      nebe09819e4514613819b7ddeb7c4caa0
    add     ah, 185
    ret

n6cf93a5a3aae44b1acec7c9cb5b8ebcd:
    dd      n416ff2c2a94f42c1be6a02af24c04159
    dd      nd6745450848e439fb99bdf86ec7575a0
    dec     ecx
    ret

n20c4978632d5443ba5d7a45e1e530933:
    dd      neb8ace4946d746038f1130ffeff6864b
    dd      nfeaeeef9ba3e4d9695082447c17b8e74
    dec     ch
    ret

n58e3c29e718245b98b83a9f036e894ef:
    dd      na9fc582685b74060b6e99ba5cd378470
    dd      n3d493b269d5d4c278644ea01200d32dd
    mov     di, 240
    ret

n7ef0248b25ac444fadded4e5672784e9:
    dd      n5f9da57ddf104152afd5cc7d8af6353c
    dd      n5daddf94668541d3ae8c1061a91851f8
    dec     bh
    ret

n99bddece1f77486e821ffe97c672bca8:
    dd      n5680725b0d544f37bd73883ef80c7454
    dd      n03febc0048e3402ba36b4100f397d40e
    dec     ecx
    ret

nffc0538b4f324c81afe38ca637c660a5:
    dd      n125215488dc24b50b95b9f9f3f82409d
    dd      nb5b90beb057b4df0ae2746fc5794e1fc
    jne     wrong
    ret

n075b5f0584b241b7a6dc43e7564e21c2:
    dd      n4fa0736cb9db4534b37efce9549a5d77
    dd      na2bfe19e542e4f649c1b73e924e1dd4f
    add     dword [51853273], edi
    ret

nd584ec595c604418b5e8cb1e77890931:
    dd      ned54de41505a40059bf20e45bc9aff9c
    dd      n1d29a98e7a8a45bc8f24e9278fce2c5e
    mov     word [55642817], dx
    ret

n5c46fbcf6b2c4df6bd8398a36448ac5d:
    dd      nfac65b44f0124526834bfcbf51ef5909
    dd      n7203cdd905f64884969bc77f31c2ecf7
    inc     dh
    ret

na746559b03824608bb75a673378693fa:
    dd      necafc0296689436687b46436058629ce
    dd      n8ce61342d9444cc4982a7fca2c88976b
    add     esi, dword [60933552]
    ret

n5b520798b98f43e3af07313297b1da14:
    dd      n6185e8bf6d324cd6b8109adbe1c31cfb
    dd      ne7a6238c5a5a4b7d9f4c6c141b7677ac
    cmp     al, byte [50568233]
    ret

nca39ac269f7e42f19f197375bc83ddcc:
    dd      ncbee7fa9cf5e405d9eedb1851f00aa95
    dd      n9138f902242549bbad701cb4cc0adbaa
    inc     si
    ret

n88e29c0e7370476cb68dedbc7ea3d4c2:
    dd      n5d7d60d2707049d78489b690419483c0
    dd      n716a79f3d69546adb7bc5b684434aae4
    xor     al, byte [password+6]
    ret

n5e831e9e47bb4173b879e8deb30f2dc6:
    dd      n73f074b682f144189130234cb394d68d
    dd      nfa475c6491a6441989dff9f3ead3eace
    mov     dl, 123
    ret

n1e056c39fcc04f8f94a7c7ba4b5ae6d8:
    dd      n1cd3d63248174c529e65c182e05d4ebd
    dd      n1a2f998edd8a4d09b274f4154b1ca21d
    inc     bl
    ret

n9138f902242549bbad701cb4cc0adbaa:
    dd      nebe09819e4514613819b7ddeb7c4caa0
    dd      n8cfedf609e974442894a58da0abdcf52
    mov     dx, word [125818566]
    ret

n17886d0d3390472b8fa628c914d3f57a:
    dd      n780f39dbb260441790324532f52ff8ed
    dd      ne73c5703034749aca069f1b4e86992ca
    inc     edx
    ret

n8bba225658f247a7be39346f282cec78:
    dd      n125215488dc24b50b95b9f9f3f82409d
    dd      n05d72dc1d1aa48258f927ac0651e510a
    cmp     dword [126150105], ecx
    ret

n821d386e73bd4e8a94aa9aca187c0b70:
    dd      n9a57cecdb9824f73bceba06b3e041369
    dd      n0dfc86b9b8e6439a8f73541de492c31b
    mov     bx, word [7129355]
    ret

n8dc1e63a904f45e597f2d85e9b759f44:
    dd      n85930114cb17467a87fddb779d87ad10
    dd      nddd040df65064f9f9e7ad5687601624f
    add     byte [133578123], bh
    ret

n853bcfcf2fcc440d93a20a4e4a787fd3:
    dd      n8dc4b39c8e174c31ad371c471d40a657
    dd      n4c2edad7a4494421a16e6a7e6a839459
    mov     eax, dword [95994178]
    ret

n6b3a49dcb0c54c2ca67a2f596b2a040e:
    dd      nc5cd8ba1af8d4c54b7ecdcd79b8bf596
    dd      neb8ace4946d746038f1130ffeff6864b
    add     cx, word [107227882]
    ret

na13aed1ba13e4f4d8849bcd6e30df1e2:
    dd      ndaddf96096c1447ca11fc034148735ba
    dd      nabbe5a10a1b4487fbe55d20aa5b0baa7
    inc     bl
    ret

nbe1b39b536254d3095a0c469a4a21a61:
    dd      n7e3da52cdce542d5a828a38297d61e89
    dd      n7cbbeab4de8041b6afeb81d17f97636e
    cmp     byte [83356663], ch
    ret

n6174e0f3a44949baa47d2f8c24e24f20:
    dd      nfb3d6071eeb846c897207f22a6cef0a7
    dd      n3f8d97f66ad64e46bc8c3c5c5f6464d8
    add     word [115824083], bx
    ret

n9c44a1baa2634057855b9845928063d9:
    dd      nc38e221b209a414787ed193cf54220c2
    dd      na2083f0ffb5249fba1528a76a0942622
    sub     word [20924825], bx
    ret

n4a99dcbaee334963b7f5b3e072f2bd4c:
    dd      n231e2dbe260549c985d0377f1d863ea9
    dd      n5e831e9e47bb4173b879e8deb30f2dc6
    sub     eax, dword [90838545]
    ret

nb7f4ec3980b44cf2afd447ec141bd3a0:
    dd      n183702569a8c4b9ca9e70a11841c5207
    dd      n16051b8df6cc4df7b38cfae0d6fab9ea
    cmp     byte [93814371], bh
    ret

n0bb1971f3c204f679e48ab9d626c8055:
    dd      nb2afbd1804d146bcbedbc96ce40e9d8f
    dd      n754eb4d816de4bf283d7862780a915e9
    add     ecx, dword [88238575]
    ret

n969cc93adfc04fbc8646689ccbca4227:
    dd      na6d1986cd8604b0485ba88916780d601
    dd      nd642fd55cae6486da7581ae2ca361f1b
    add     dword [60971545], esi
    ret

n5fbec9ac907d4e2aa95ea291e9b6ddbe:
    dd      n67a1fd7364654cc0869537addb79a9f2
    dd      n03febc0048e3402ba36b4100f397d40e
    add     dword [106318091], edx
    ret

n8670f32eabd242aabfc51097b3bb73eb:
    dd      nce69d096231d45989160e5f54570ead0
    dd      n94d5cd843b3b4fe09642878b4b22d1c1
    sub     ah, byte [30828525]
    ret

na367e6ebcd244100bcc900ff95ac3aa0:
    dd      n977e5c293d2f46bb91772215f8f95b3c
    dd      n1ffbc7474ffb426ca04e589f7f96ecb4
    add     al, byte [125424649]
    ret

start:
    dd      nd55edcb0a6af41daac76f764ca4d1e08
    dd      n8a844eb598e24548926ebfe56b03db68
    mov     eax, 4
    ret

n3bda26cdb1834182b6720e99550d1787:
    dd      n125215488dc24b50b95b9f9f3f82409d
    dd      n315013e932ca4c33bd14169eba88741a
    inc     cl
    ret

n0042ce7382ee4cdfbbf04b03799d6917:
    dd      n7e31bc20613f42fe961dc5b38a1936ff
    dd      n48f512b07ed741429d4417dfdea79b9b
    inc     edx
    ret

n633e47ce3bc84cbdb7be4aef2b86a4ff:
    dd      n4b3f95fe70644aff960f49861088391e
    dd      nd0ca3d7696234937aa141ba949d578ec
    mov     si, word [125466177]
    ret

n895aacf0e4774e64a68b41036ecf2d5f:
    dd      nc38e221b209a414787ed193cf54220c2
    dd      nd7baf9cb766949d1a4a79d5b148df0e5
    inc     edi
    ret

n7490a6c6d79f4db7aaff71ab283ad629:
    dd      nfda1bf9b1122413fadf2c42e0094d105
    dd      na13aed1ba13e4f4d8849bcd6e30df1e2
    inc     bx
    ret

nfdc994f17ced41e8982b4366249b785d:
    dd      n4c2edad7a4494421a16e6a7e6a839459
    dd      n02f2b7867b3f45a2b8e2a021bbce484b
    jne     wrong
    ret

n3e88a737c7c9425db4684acdb9bf804d:
    dd      nd7cba4a2e5f1407aab2a889d7d880a4d
    dd      n50c35b6396794f369584b4b2c03a2412
    cmp     ebx, 213
    ret

n429cad16f40644d1b1ad3ad713b16e6e:
    dd      n75832cdd7450497394ed76ff23cfd623
    dd      n85c22a9cfdb24dc383b9928ebe98464e
    mov     ebx, 202
    ret

n3959cfc3d2474ae69d9073555478eb41:
    dd      ne1fe1623fb374959bffeb9f38d19c4d6
    dd      nc4dc80dc7a7748a7935bc9ba9d913cb5
    test    edx, edx
    ret

n66c0089428af4e38a243cb1606dd709b:
    dd      n19f10ea182c7477e987d194528d826ea
    dd      n8d9e5eec97c14eef8d60306ddaf478aa
    wrong:      inc     edx
    ret

n23ffb80afc7240fcaec9263bec31019e:
    dd      n3b53ddf0c21d448890519f79d9387913
    dd      nc3fb6d9341414899a962f08c6ad86613
    cmp     bh, 74
    ret

nea549e8f387a4766bfd9953187061c1e:
    dd      ndb71519c622345a0b997f366a5a1d1d5
    dd      n2969a1c209354b0e9782709d2ea5b349
    mov     di, word [103134489]
    ret

n8d9e5eec97c14eef8d60306ddaf478aa:
    dd      nafd3c3e0b1f74b82bcc1d0a25f8915ac
    dd      nbcdc253ea7534f158d056525d48924a4
    add     ax, 132
    ret

nf737d25b2be641cabb9cbbd05752708e:
    dd      n4a99dcbaee334963b7f5b3e072f2bd4c
    dd      n9e668ae7b2544bde851f0793955c0289
    mov     byte [98444086], al
    ret

nadd9bbb9a2cd476d98d4e424e9c47c55:
    dd      n0352ee27c2ee47819b00d5b3a4615bdd
    dd      n13b8f652fb724e879c3e0fda98cff7b2
    sub     dword [114098860], ebx
    ret

na32f178dfe09492a9d635c8bf29bb07c:
    dd      n2cf991af9811445a95a73748261bdea3
    dd      n4fa0736cb9db4534b37efce9549a5d77
    cmp     cx, word [10411647]
    ret

naa3553b3c5c74ecd81d37a803a2759b4:
    dd      nee928b82cd3a4c66ad43b6d6951a9872
    dd      n593974439a694ec9a41da67491df427c
    sub     ax, 133
    ret

n3d11fd72da04432fbd60b415a96824a6:
    dd      nffe7c0690c3e400a9dee8b27613b7aed
    dd      ndaddf96096c1447ca11fc034148735ba
    dec     dh
    ret

n73087da804774be09608e8026f9e966d:
    dd      na726c4fe15f440b8ad7e7c1af5780d04
    dd      n3f8d97f66ad64e46bc8c3c5c5f6464d8
    dec     ebx
    ret

n37a63955e76a4030a19655a7660d78fb:
    dd      n3e3d7547302844cd8b9487fe8ad1a564
    dd      nd6745450848e439fb99bdf86ec7575a0
    inc     di
    ret

n16051b8df6cc4df7b38cfae0d6fab9ea:
    dd      n2dcdd8b795294b068f27c0cce9543966
    dd      n768fedc792174092b44b8ee045a13627
    add     ax, word [63416035]
    ret

nf4e8c98ab09a4459b428df02d6b6be2c:
    dd      nd7baf9cb766949d1a4a79d5b148df0e5
    dd      n66c0089428af4e38a243cb1606dd709b
    cmp     dword [22901089], esi
    ret

n6ec324cbacb2493eb80bd97ab71572a4:
    dd      nddaf32feafd74be2a5429c8efc8e0ffb
    dd      n146aed7b5a37439ea848f58c5547e0f1
    cmp     ecx, dword [19279115]
    ret

n8179f5a0fe6d4c6dac74ef378fb98991:
    dd      n010f30611e76493cb6d7dc5cdf196703
    dd      n5daddf94668541d3ae8c1061a91851f8
    inc     bl
    ret

n878a77636b344c77b3c5824ae17bcb95:
    dd      n9c39cfd1ae074758bfd9ce71512ca022
    dd      n372b3dfb9b834363b0a4d58ad8bff2f0
    sub     ecx, dword [100346907]
    ret

n731d413f02824f398e503d23d5ed3892:
    dd      n801a4b3cdbfc4100916f0fcf83353a30
    dd      n5d7d60d2707049d78489b690419483c0
    mov     dh, byte [86857500]
    ret

n13b8f652fb724e879c3e0fda98cff7b2:
    dd      na424657efade46718c69647b8b136ada
    dd      n2833d968433941459af9669b5dd59c71
    add     al, 0x13
    ret

n5e82d9b9a55d4e1987919e1462ac1080:
    dd      n969cc93adfc04fbc8646689ccbca4227
    dd      nc4e9a20f15f6409a8e775a0196d26e80
    sub     al, byte [44112327]
    ret

nc38e221b209a414787ed193cf54220c2:
    dd      n2dcdd8b795294b068f27c0cce9543966
    dd      n4a78061052ca4bfd9c6f1ced7805659d
    add     ch, byte [51287310]
    ret

n42c03f573d0d43589ac041188951c32b:
    dd      n4cde16b6cd544de98795772b18b6b481
    dd      n105b14e69e914d8d9bca4c07aef40af2
    sub     edx, 45
    ret

n6af3470de00b4eb196299c45c121249a:
    dd      nc3b4d643c88746c6a5e01ee9b1f6d433
    dd      n5e82d9b9a55d4e1987919e1462ac1080
    cmp     byte [127056696], ah
    ret

n05d72dc1d1aa48258f927ac0651e510a:
    dd      n7ef0248b25ac444fadded4e5672784e9
    dd      na81735aebec240b6867724ddde765169
    xor     al, 0x72
    ret

nd7b9cbd318d34fa688beade21a94cb01:
    dd      n315013e932ca4c33bd14169eba88741a
    dd      nf574803ad1124ff8af417be02e01651a
    add     word [63543381], cx
    ret

ne0c6b4fbeb7e4d0989a47d968dff254d:
    dd      nb64eec799e274ba0858474d679ff733d
    dd      n7e661504a1504134b69ccae812dcedd0
    inc     di
    ret

nf4cc94a4b239462f8ff7199a2981a736:
    dd      n89a7a87978274ce4bb01bedf95ec20b7
    dd      n3be4e9a16938459a89e0b5102df643f6
    dec     dx
    ret

n7e3da52cdce542d5a828a38297d61e89:
    dd      n66c0089428af4e38a243cb1606dd709b
    dd      na9fc582685b74060b6e99ba5cd378470
    password:   db      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ret

n1ffbc7474ffb426ca04e589f7f96ecb4:
    dd      nd974e7f33bda4ec5b5ebef3724a21e09
    dd      na890ca84908c479bb53b29ee50a8d4e6
    add     al, 176
    ret

nd44147b405904c58aa5486a649223efe:
    dd      n0e598ab1b2ce4781888d816744d2b7a6
    dd      n8cfedf609e974442894a58da0abdcf52
    add     byte [95237631], bl
    ret

nc96723d13d7b483ca45c9592e968da63:
    dd      n2dcdd8b795294b068f27c0cce9543966
    dd      n5f9da57ddf104152afd5cc7d8af6353c
    inc     di
    ret

n9351c0dce0244920b29057970f4a9674:
    dd      n754eb4d816de4bf283d7862780a915e9
    dd      n76bba4a5b17940ee90d80c8f8893ca7d
    dec     dx
    ret

n4750902797504585be24b2e3dc2f8736:
    dd      n597711df0d424df687d58e5533aba8e6
    dd      n7e661504a1504134b69ccae812dcedd0
    cmp     word [62006821], di
    ret

nf716cc477d4146d5a43fe814d7176d46:
    dd      n1f455765812947c88170728a89594cae
    dd      nfd5ba5844c0848a888f033e524132cfe
    dec     al
    ret

n246a54c4644247a399c3c9a645580993:
    dd      n9a8e9caceff44afca43e554b3db71fff
    dd      nb51e6c3001e04203930c9174f0a7d90b
    dec     ecx
    ret

n1773c162205f4acfb6f738ad293d7611:
    dd      n5d7d60d2707049d78489b690419483c0
    dd      ncbee7fa9cf5e405d9eedb1851f00aa95
    cmp     word [65178459], bx
    ret

n44b53204a9104067b9846f5451225afa:
    dd      nbcdc253ea7534f158d056525d48924a4
    dd      n953cfc0f24914bd5bdf468152e558f70
    inc     dx
    ret

n2cf991af9811445a95a73748261bdea3:
    dd      nabbe5a10a1b4487fbe55d20aa5b0baa7
    dd      n8d85b96cea1447d38444ef5af62441da
    dec     si
    ret

n999d3c6b6d454beb867898d70778d6c6:
    dd      n8ce61342d9444cc4982a7fca2c88976b
    dd      n1a18a9386ba844f397c63c2b3e22b865
    dec     eax
    ret

n1d29a98e7a8a45bc8f24e9278fce2c5e:
    dd      nb632684b1f6341f6813a0802d95923e4
    dd      n0042ce7382ee4cdfbbf04b03799d6917
    cmp     al, 0x21
    ret

na9a654ffa33447c995eceae05369bd90:
    dd      n5086ccea82464136bf668df67b7a5fce
    dd      n0a1d734cdbdd445284e466a5b10e0ce3
    cmp     word [14107555], si
    ret

n0e7141720e7f4d679f6da0d95c5483bd:
    dd      n1f44633b9e884a41aef9f6fa5e991ebf
    dd      n633e47ce3bc84cbdb7be4aef2b86a4ff
    inc     ch
    ret

nb8e714736cc7478eaf0d66bd45db5be8:
    dd      nda5d3d732757443d9c5fdecbb07be84c
    dd      n7203cdd905f64884969bc77f31c2ecf7
    inc     bx
    ret

n1595ee4a001741b3879545e020b3f5b9:
    dd      n7e564f0ebd16445195a65891ef22f6c5
    dd      n8cfedf609e974442894a58da0abdcf52
    cmp     al, 0x57
    ret

nc2c48b7e31a74a2dbe4db6fcdcbe0c3a:
    dd      nbc5d138188e84abd9ed8681eb52bcc54
    dd      n63e4dff5950349d589859194b113b2dc
    mov     al, byte [password+15]
    ret

n38cdc1a25b6c47669598960e5684f01b:
    dd      na2bfe19e542e4f649c1b73e924e1dd4f
    dd      nddaf32feafd74be2a5429c8efc8e0ffb
    dec     ah
    ret

nffe7c0690c3e400a9dee8b27613b7aed:
    dd      n98846aca46b9451cb9bea8c41ba39411
    dd      n0b0e639acb7e43f3a6b47a38207bf9e7
    inc     ebx
    ret

n27beb4c16c144e94b6dec287731a2ff2:
    dd      nd6745450848e439fb99bdf86ec7575a0
    dd      n9138f902242549bbad701cb4cc0adbaa
    add     di, 105
    ret

n3222e07d0c514015a6633261bd3365b1:
    dd      n597711df0d424df687d58e5533aba8e6
    dd      n1cc86827fd2f4961a10140f17fbcb55e
    cmp     al, 0x71
    ret

n1e64eb2634ac4667b79882895e675339:
    dd      nfda1bf9b1122413fadf2c42e0094d105
    dd      n6174e0f3a44949baa47d2f8c24e24f20
    inc     cx
    ret

n2e116b13467d47ae882f84ad7bcd898f:
    dd      n94d5cd843b3b4fe09642878b4b22d1c1
    dd      n85930114cb17467a87fddb779d87ad10
    xor     al, byte [password+12]
    ret

nc8821a57aefb4505a7417b9ab23894ba:
    dd      nf4e24a2b07be427f94f1c2dae52b6c02
    dd      n2209c5a15d084d7db92885414bab7791
    mov     di, word [47702292]
    ret

n8755974bc5dd4c22aa4b2afa04bf3118:
    dd      n2ac793d5528d4a5486fdbd244fe6e56a
    dd      na9fc582685b74060b6e99ba5cd378470
    mov     word [91122662], di
    ret

ne1d743464bc84cd4b2c7311fb98eb254:
    dd      n1f44633b9e884a41aef9f6fa5e991ebf
    dd      nddaf32feafd74be2a5429c8efc8e0ffb
    sub     esi, 35
    ret

nd7cba4a2e5f1407aab2a889d7d880a4d:
    dd      nd9b5c40a883847ca89becaf84d37a48f
    dd      nacce8e8728df46b494499e28c8c426bb
    inc     dl
    ret

na43c07a43b554471ab233ad8a42a0e22:
    dd      n13b8f652fb724e879c3e0fda98cff7b2
    dd      n0e7141720e7f4d679f6da0d95c5483bd
    mov     al, byte [password+2]
    ret

n77ae320a7dbf4447bca9976bad0666de:
    dd      nb26520eeac0e476585f023920cc2210f
    dd      nc452026c1f6a49bab3dbd76554f540b4
    sub     word [19912713], cx
    ret

n6c20c1a9869d4de2b5d5be0fdcb5d51e:
    dd      n864518d5da21446bb4488208e2a4c414
    dd      n05d72dc1d1aa48258f927ac0651e510a
    mov     al, byte [password+5]
    ret

n9e668ae7b2544bde851f0793955c0289:
    dd      n474371fa30b048048425b47821140c53
    dd      nb8acb7da1297410bacc2ccaef3adb2c3
    mov     edx, dword [105854812]
    ret

n064722e97de14fb58b79989a18573e10:
    dd      n460ecaa233db4ca296d51d53a5e7d917
    dd      nc3b4d643c88746c6a5e01ee9b1f6d433
    dec     dh
    ret

n666fa0c3e7ae488b99cd04b9f5707223:
    dd      nc0a020f6b8c0404e88636253629172c3
    dd      nddaf32feafd74be2a5429c8efc8e0ffb
    cmp     dh, byte [75553659]
    ret

n916264c9c532434bb584774c3abd0091:
    dd      nf84a7ae9c6ff4b8d8aae8b65b71bb8d7
    dd      nf38fbfe213f64dfa947a24c00b403cac
    sub     si, word [72715993]
    ret

n536cd072ccd44d2eaf6b0015514ca97e:
    dd      nfda1bf9b1122413fadf2c42e0094d105
    dd      n14f738b864b640149d1fc8106b247666
    inc     bh
    ret

n46fa6e7590bf4a979a3040be77ab1f1d:
    dd      n864cc51eff834bb0be61afcd15d66fa5
    dd      n895aacf0e4774e64a68b41036ecf2d5f
    mov     ebx, 0
    ret

ne7a6238c5a5a4b7d9f4c6c141b7677ac:
    dd      nf49716b112d64a8d9fb69476de8c7bca
    dd      nf6e627d9ef63425b802e2649598dc8b9
    mov     dh, 167
    ret

n953cfc0f24914bd5bdf468152e558f70:
    dd      n932699cc74fa486ebdb6f7495187dfb7
    dd      nbf13ef9fb9844f86b19576141994b442
    mov     ch, byte [7258165]
    ret

n7bd65bfcdadd4949ada66a2345ae9fcb:
    dd      na3f3cdfd1abc4439b1b326f25f19496f
    dd      na846af1c232748ba9529a6edd93ad359
    cmp     word [54977875], si
    ret

n65d42bad64eb4f60ad8a65e8ffef6d8c:
    dd      naf3d48576c214433860b4fbe2708b268
    dd      n17886d0d3390472b8fa628c914d3f57a
    sub     edx, dword [273082]
    ret

nc4e9a20f15f6409a8e775a0196d26e80:
    dd      nad52ede8c51d4ab88a787f5110016da9
    dd      nb4028fa20e974454a9b038e0abf52c87
    mov     edx, 20
    ret

n998b047ea4b541e1ae1ff74907433cdb:
    dd      n44ca1f2c6f364a09a070f7d3d2018991
    dd      n89fb381f1748438391e9bc963a8e7320
    cmp     byte [64540273], bl
    ret

n213aa6d4059c4a008ee109d6eee8f87e:
    dd      n79a72970e5ba457aa1eab2b0b52e26d2
    dd      n4a99dcbaee334963b7f5b3e072f2bd4c
    sub     byte [24954038], dl
    ret

n6c3799747d4046758bfb19d8d01258c8:
    dd      n4086554cd5c849afa03e7c887e10b1df
    dd      n4750902797504585be24b2e3dc2f8736
    inc     ch
    ret

n71b45a671f724855acaa8e1cd983f074:
    dd      n2e31c92b141e41b0bbfa521d916eece2
    dd      ne2c3553cb74a47dfb24949afacd9b21f
    sub     ebx, dword [99022978]
    ret

n629047d6711840669924c151ca0d8543:
    dd      nb310b0dc521e4a5cbfff1519a88c3636
    dd      na846af1c232748ba9529a6edd93ad359
    add     word [51726561], cx
    ret

n75832cdd7450497394ed76ff23cfd623:
    dd      na367e6ebcd244100bcc900ff95ac3aa0
    dd      n675acff081f54b89920fbcb96e7d0209
    cmp     byte [49908009], ch
    ret

nfb3d6071eeb846c897207f22a6cef0a7:
    dd      n94f990aaa41848a890bff123a404ef29
    dd      nf79fb368b600466f9fe4d4db3a4737da
    add     cx, word [69315936]
    ret

n8d9ce83285094cc9967ccedad8870242:
    dd      n999d3c6b6d454beb867898d70778d6c6
    dd      n0dd1a486038a45728ba0ef206705d654
    sub     dword [52081639], ebx
    ret

n19043426c5ea48fb9719f43c22b0c9ee:
    dd      n1595ee4a001741b3879545e020b3f5b9
    dd      n38fb10a412ed439ba7c8f722e54d4646
    xor     al, byte [password+4]
    ret

na890ca84908c479bb53b29ee50a8d4e6:
    dd      n06cb9599a24d4623a2120542f6fa0b48
    dd      na746559b03824608bb75a673378693fa
    inc     ah
    ret

nfea2e9fc9ec7437fac4f0240b890bf38:
    dd      nec7891a2d33f44ef9d9067be0e79b515
    dd      n969cc93adfc04fbc8646689ccbca4227
    dec     edi
    ret

n1cc86827fd2f4961a10140f17fbcb55e:
    dd      na3eefeec12694b62b7bd1090cd22ee7f
    dd      n0dd1a486038a45728ba0ef206705d654
    jne     wrong
    ret

n4fa0736cb9db4534b37efce9549a5d77:
    dd      nd475c2bdcfa846b9954c6ccd367702fc
    dd      ndc98ae68464f407eb2f3ca5f14383316
    mov     ah, 166
    ret

n010f30611e76493cb6d7dc5cdf196703:
    dd      nfda1bf9b1122413fadf2c42e0094d105
    dd      nbc5d138188e84abd9ed8681eb52bcc54
    mov     esi, dword [63339489]
    ret

n9fa9353c97574f55ad03624c99cd445c:
    dd      n2dcdd8b795294b068f27c0cce9543966
    dd      n675acff081f54b89920fbcb96e7d0209
    inc     dx
    ret

n19f10ea182c7477e987d194528d826ea:
    dd      n7ef0248b25ac444fadded4e5672784e9
    dd      nb62538f43b854d23988843fcdfe1f384
    set_wrong:  mov     ecx, incorrect
    ret

n0d6c9e09e1684adbb2e0f01a5e593c00:
    dd      n754eb4d816de4bf283d7862780a915e9
    dd      n2969a1c209354b0e9782709d2ea5b349
    cmp     dword [86545866], esi
    ret

nb3425231937741e88bac48027690bec7:
    dd      n39a5b81fb07e48999cc7ec94e692fff2
    dd      n85930114cb17467a87fddb779d87ad10
    cmp     dword [84197093], ebx
    ret

n59bffc56972342478b322ec200f72e74:
    dd      n416ff2c2a94f42c1be6a02af24c04159
    dd      n694a321ddf124add8d221d20bf0b3465
    jne     wrong
    ret

n757a6b21bc8d49629510e95f20c01a2e:
    dd      nda82b1a578b54cb2ac2d9b78bd1ac130
    dd      n3be4e9a16938459a89e0b5102df643f6
    mov     cl, byte [password+10]
    ret

n2aaf1a265fbc4f97a7c28740e1670079:
    dd      n818a89cb7d8a4bfa917cfca7efa7c9a0
    dd      nebe09819e4514613819b7ddeb7c4caa0
    mov     esi, 125
    ret

n93698713774c402b87f6bf7b3690a2dd:
    dd      na3eefeec12694b62b7bd1090cd22ee7f
    dd      n0e7141720e7f4d679f6da0d95c5483bd
    mov     dword [118974209], edx
    ret

nb544503268df4b19a140a7e4e07af025:
    dd      nb49acae0567d455490aad378d7e29d97
    dd      ne1d743464bc84cd4b2c7311fb98eb254
    mov     al, byte [password+7]
    ret

n2dcdd8b795294b068f27c0cce9543966:
    dd      n46fa6e7590bf4a979a3040be77ab1f1d
    dd      na0383f040b9d4615a9eaddd7509e8ff3
    sub     dword [103709733], esi
    ret

n09319cad14c84d35a800235de03b10f1:
    dd      na85e0595fcfe4b5286a281ee22b6559c
    dd      n435cf42334264eb4b8929ca1bd432487
    xor     al, byte [password+10]
    ret

nf84a7ae9c6ff4b8d8aae8b65b71bb8d7:
    dd      n977e5c293d2f46bb91772215f8f95b3c
    dd      n6174e0f3a44949baa47d2f8c24e24f20
    inc     ecx
    ret

neb86cf7ba6904475a079765580056f4c:
    dd      n14be4e4bb7284845a29d0ce2d2d9d912
    dd      nbf13ef9fb9844f86b19576141994b442
    inc     dx
    ret

n1451c64158694a05994d25ce70e6ca70:
    dd      nec03156657f34feeabe5e90386f80b7f
    dd      n8d85b96cea1447d38444ef5af62441da
    cmp     ah, byte [27844285]
    ret

nf8f97559219d437180f964b709b9a0a6:
    dd      neca51d4f7b374be2b8e42ca810a71e0c
    dd      n0df1cebbb2d6428588a89cb71cbe3daa
    cmp     al, al
    ret

n8ad89a1ecf574a858465f4e7f81093c6:
    dd      na2c53f927d944691ae7233385fb8f410
    dd      na846af1c232748ba9529a6edd93ad359
    inc     edi
    ret

n89a2d3a1f2674c1c948605d5a531abf3:
    dd      n8179f5a0fe6d4c6dac74ef378fb98991
    dd      nb7553349f2454559ac3aa224d5e2e86c
    xor     al, '{'
    ret

na2083f0ffb5249fba1528a76a0942622:
    dd      nd6745450848e439fb99bdf86ec7575a0
    dd      n5daddf94668541d3ae8c1061a91851f8
    cmp     bl, 249
    ret

n0bdcecfad55b408899fb75e985d4a175:
    dd      n2d034e0326254dec9962b5cf88076b3f
    dd      n593974439a694ec9a41da67491df427c
    sub     ebx, 153
    ret

n683c40c8e54b471ea460f7db225b0546:
    dd      na7ddebfd7ba14f2f957c11411d7a0b5c
    dd      nc3fb6d9341414899a962f08c6ad86613
    sub     dh, 187
    ret

nd92b308cfcdf42a9892f0a9f96dcb870:
    dd      n4ea0c1362ca5448193daeead0d04b9fb
    dd      nc186e74177e64b6b999ab06bd110641d
    inc     ax
    ret

nca53931648784b7c9014682b57f6c263:
    dd      nbe1487e18b8b47b5975d980a0e748d3a
    dd      n14be4e4bb7284845a29d0ce2d2d9d912
    dec     dl
    ret

n0e598ab1b2ce4781888d816744d2b7a6:
    dd      n4db4d5a4983748f5809dc0190b461640
    dd      na2c53f927d944691ae7233385fb8f410
    cmp     ch, 75
    ret

nb7e2ec18e52e4bb2b63b16fd868c6523:
    dd      n994e10e8a0854f6ba1ae23dbba779e6b
    dd      n4bd8f0a6da3f4094b33007f884d7dbd3
    mov     al, byte [password+4]
    ret

n79a72970e5ba457aa1eab2b0b52e26d2:
    dd      nadd9bbb9a2cd476d98d4e424e9c47c55
    dd      nec03156657f34feeabe5e90386f80b7f
    dec     ah
    ret

nc0a020f6b8c0404e88636253629172c3:
    dd      nd584ec595c604418b5e8cb1e77890931
    dd      nbe1b39b536254d3095a0c469a4a21a61
    inc     ch
    ret

nd642fd55cae6486da7581ae2ca361f1b:
    dd      n34d6e76f705c48dfbd4a26a016c9d0be
    dd      n99f24fa864ee40f68254432c94a48c3e
    dec     edx
    ret

n09f97fcf2be8423fb7eac7e79924ebac:
    dd      n51724631270c43008a8b34a64db85d41
    dd      nd0ca3d7696234937aa141ba949d578ec
    sub     dword [130020281], edi
    ret

n23b6aa6a11b545df9bf0262ee1ac11c1:
    dd      n8755974bc5dd4c22aa4b2afa04bf3118
    dd      nf4e24a2b07be427f94f1c2dae52b6c02
    inc     edi
    ret

nf4e24a2b07be427f94f1c2dae52b6c02:
    dd      nd896a85d040544d5ab6d057fff5e342d
    dd      nb582d43b32b24e4baa337fb48afbe2ba
    inc     dh
    ret

n64332f29ce51490a9ebc01255027d374:
    dd      n88e29c0e7370476cb68dedbc7ea3d4c2
    dd      nf79fb368b600466f9fe4d4db3a4737da
    xor     al, byte [password+7]
    ret

ne6786640a13d42018a205f8ff4f5dc42:
    dd      n4cec7cc36ef149c48ee5107f8c3d7ead
    dd      n300c285ed94a47ec9cd12614ae2de3fd
    sub     byte [92071286], ch
    ret

n105b14e69e914d8d9bca4c07aef40af2:
    dd      ncbf85b0b9ca64479a4232f2cbf28f96e
    dd      nfda1bf9b1122413fadf2c42e0094d105
    sub     word [17391359], bx
    ret

nec03156657f34feeabe5e90386f80b7f:
    dd      nf7e21a6350144d48a4f4128fe4dc0450
    dd      n665b80eefd7342faa665b5848669393f
    dec     ch
    ret

nddaf32feafd74be2a5429c8efc8e0ffb:
    dd      nc3fb6d9341414899a962f08c6ad86613
    dd      n593974439a694ec9a41da67491df427c
    mov     edx, 251
    ret

nfc2a0cdae74a4a1f992bfa2618bb6b6c:
    dd      n1f44633b9e884a41aef9f6fa5e991ebf
    dd      n2e116b13467d47ae882f84ad7bcd898f
    cmp     word [44529811], di
    ret

n675acff081f54b89920fbcb96e7d0209:
    dd      n1a91488d469f428abe38c183fca0de1d
    dd      n79a72970e5ba457aa1eab2b0b52e26d2
    inc     dx
    ret

nf4e75c89173647c78469fdc93c5085a4:
    dd      neb8ace4946d746038f1130ffeff6864b
    dd      n2e116b13467d47ae882f84ad7bcd898f
    xor     al, byte [password+13]
    ret

n3b53ddf0c21d448890519f79d9387913:
    dd      n44ca1f2c6f364a09a070f7d3d2018991
    dd      n075b5f0584b241b7a6dc43e7564e21c2
    inc     si
    ret

ned54de41505a40059bf20e45bc9aff9c:
    dd      n757a6b21bc8d49629510e95f20c01a2e
    dd      n0b0e639acb7e43f3a6b47a38207bf9e7
    mov     bl, byte [password+5]
    ret

nb78350ff87cf40378f7155704443b2d7:
    dd      n3959cfc3d2474ae69d9073555478eb41
    dd      n63e4dff5950349d589859194b113b2dc
    mov     ecx, correct
    ret

n7a034e59451a47dabc3a9118adb3161a:
    dd      n09319cad14c84d35a800235de03b10f1
    dd      n0e598ab1b2ce4781888d816744d2b7a6
    sub     edx, dword [90319898]
    ret

necafc0296689436687b46436058629ce:
    dd      n5086ccea82464136bf668df67b7a5fce
    dd      n1f455765812947c88170728a89594cae
    mov     al, byte [password+6]
    ret

na8309a29a7304d078d899b7898126dfd:
    dd      n56bc96cb21e84eaead5b189376ec853f
    dd      n50d8e9abacfa41f2bd8c73ce44ccbf53
    xor     al, byte [password+3]
    ret

n241e74d22bd442c7a9a10662aa5480e9:
    dd      ne1fe1623fb374959bffeb9f38d19c4d6
    dd      n00fa8e64b3f14195a740ab08b1a0f30f
    mov     dword [21873380], eax
    ret

nc5cd8ba1af8d4c54b7ecdcd79b8bf596:
    dd      n06a305311e834824b2c3e36d28d6c19c
    dd      n8d85b96cea1447d38444ef5af62441da
    mov     al, byte [password+10]
    ret

nbbd8c9eca97b44b3b5170caed6b3b370:
    dd      n63e4dff5950349d589859194b113b2dc
    dd      n4c2edad7a4494421a16e6a7e6a839459
    sub     dword [90022591], edx
    ret

na4a144a932ee430db4765fc978e119c7:
    dd      nf49716b112d64a8d9fb69476de8c7bca
    dd      n0c808626718c466789a6c9165df0dca1
    sub     byte [84427539], dl
    ret

na3a08542b29b49c383d869dc6fcd69f8:
    dd      nc328a807fe3c472da79dfefbd2040652
    dd      n2e020de9c2ad41b193c6587afc39b40b
    inc     dh
    ret

na86c58288c4b4e2faafc7a84474dd8ff:
    dd      na7ddebfd7ba14f2f957c11411d7a0b5c
    dd      n36acad7124b54538980d6d057d4ef951
    mov     ecx, password
    ret

n51724631270c43008a8b34a64db85d41:
    dd      n932699cc74fa486ebdb6f7495187dfb7
    dd      n895aacf0e4774e64a68b41036ecf2d5f
    inc     eax
    ret

n146aed7b5a37439ea848f58c5547e0f1:
    dd      nef286e8333f14ac5bf0f0ee8e4b8f9cf
    dd      nf79fb368b600466f9fe4d4db3a4737da
    inc     bx
    ret

n7271295e9a134c1f87e570d9c5d523e3:
    dd      n8e830f95f71d4204bc6ea8e992ca546d
    dd      nbe1b39b536254d3095a0c469a4a21a61
    cmp     byte [131333205], bl
    ret

nb51e6c3001e04203930c9174f0a7d90b:
    dd      nba025563875b48d7b86671ab4f856f01
    dd      nf60fb3f969b949cfac97bdd6a77ce1a0
    sub     dl, 102
    ret

n4c2edad7a4494421a16e6a7e6a839459:
    dd      nafd3c3e0b1f74b82bcc1d0a25f8915ac
    dd      nea105b6bf99c437aa32d79e7d035e61f
    dec     cx
    ret

n7cbbeab4de8041b6afeb81d17f97636e:
    dd      n16051b8df6cc4df7b38cfae0d6fab9ea
    dd      na3eefeec12694b62b7bd1090cd22ee7f
    inc     di
    ret

na3eefeec12694b62b7bd1090cd22ee7f:
    dd      n53c54afe020746a6a947892955670970
    dd      n880635899a114bf1b7bae4af840d68ac
    dec     eax
    ret

n4cec7cc36ef149c48ee5107f8c3d7ead:
    dd      nf420c1a059b5498cbdff555595c6576f
    dd      n19c3cd605ff6432a95a6b9f5affd5939
    sub     esi, 79
    ret

n11840b18effb4282ba1fe11abe59ba18:
    dd      n621e3fbc6fb34509a61f1e40390ac910
    dd      n3d4a16c163b54f9096afd61c6e54c4a6
    sub     ch, byte [32070901]
    ret

n67a1fd7364654cc0869537addb79a9f2:
    dd      n675acff081f54b89920fbcb96e7d0209
    dd      nb4d7c40b60e14e4ca4fe3b201df2bfee
    cmp     dx, word [6164154]
    ret

ndda70f3f37f14b4b8a18eb222be6ccf8:
    dd      n2833d968433941459af9669b5dd59c71
    dd      n002b481fe6fb484fb99037f5a2e3d6a8
    dec     bh
    ret

neca51d4f7b374be2b8e42ca810a71e0c:
    dd      ne4ca22c1effc400d8872adcaafdcb765
    dd      n6c20c1a9869d4de2b5d5be0fdcb5d51e
    jnz     wrong
    ret

nf38fbfe213f64dfa947a24c00b403cac:
    dd      n8dc1e63a904f45e597f2d85e9b759f44
    dd      nddaf32feafd74be2a5429c8efc8e0ffb
    cmp     di, 22
    ret

n14328ebb2280424faba0e9d75de913de:
    dd      ne391fd837e9b4b708dac1272afc64763
    dd      nfa475c6491a6441989dff9f3ead3eace
    add     si, word [75152578]
    ret

n48f512b07ed741429d4417dfdea79b9b:
    dd      nff33a9e19452470f95e063004eb982b3
    dd      n7e31bc20613f42fe961dc5b38a1936ff
    inc     bl
    ret

n94f990aaa41848a890bff123a404ef29:
    dd      naa3553b3c5c74ecd81d37a803a2759b4
    dd      n94f990aaa41848a890bff123a404ef29
    mov     esi, dword [42830146]
    ret

n002b481fe6fb484fb99037f5a2e3d6a8:
    dd      n77193e3e51cd472f864d456f707184cd
    dd      n895aacf0e4774e64a68b41036ecf2d5f
    sub     ah, byte [75607908]
    ret

n16906ee689564b8c965fdde853550a4a:
    dd      n466522d5d73e4ff39cf2185020a38c0a
    dd      n02090a12e2db4d77bd753622c78a2b33
    cmp     al, 'c'
    ret

n8d0db37147a74c59890a2fe35b402860:
    dd      n52ae5a262d1041288ccf9a05b03a5ebe
    dd      n16906ee689564b8c965fdde853550a4a
    mov     ax, word [134362720]
    ret

n9833ad5165a64011874aa22c4291eb18:
    dd      n5daddf94668541d3ae8c1061a91851f8
    dd      ne99671391f654a65a995470855fecd05
    dec     ax
    ret

n72e0bcc46b05403d93321e2f885bc680:
    dd      n4cec7cc36ef149c48ee5107f8c3d7ead
    dd      nb8e714736cc7478eaf0d66bd45db5be8
    sub     byte [108638481], dl
    ret

nf3f9bd326c5f46cd9c6e7a56220369ca:
    dd      ncbf85b0b9ca64479a4232f2cbf28f96e
    dd      n7e3da52cdce542d5a828a38297d61e89
    incorrect:  db      'Incorrect :(', 10
    ret

na3f3cdfd1abc4439b1b326f25f19496f:
    dd      n5fbec9ac907d4e2aa95ea291e9b6ddbe
    dd      n77193e3e51cd472f864d456f707184cd
    inc     dl
    ret

nef286e8333f14ac5bf0f0ee8e4b8f9cf:
    dd      n6b3a49dcb0c54c2ca67a2f596b2a040e
    dd      n2e116b13467d47ae882f84ad7bcd898f
    sub     dword [94900465], ecx
    ret

nfac65b44f0124526834bfcbf51ef5909:
    dd      n9b4434d551ff46aa8a10d689d3cfe93e
    dd      n58e3c29e718245b98b83a9f036e894ef
    mov     word [113295232], bx
    ret

n460ecaa233db4ca296d51d53a5e7d917:
    dd      na2df715b7f3846ebbd59e736b767be08
    dd      ncbf85b0b9ca64479a4232f2cbf28f96e
    add     dl, byte [73053248]
    ret

naf3d48576c214433860b4fbe2708b268:
    dd      ndaddf96096c1447ca11fc034148735ba
    dd      na2bfe19e542e4f649c1b73e924e1dd4f
    dec     dl
    ret

nda5d3d732757443d9c5fdecbb07be84c:
    dd      nbe1b39b536254d3095a0c469a4a21a61
    dd      ne95b2c715a75459fb9068cf6decfede6
    inc     edi
    ret

n395b7d9964154369874277368d457761:
    dd      nfea2e9fc9ec7437fac4f0240b890bf38
    dd      nb3425231937741e88bac48027690bec7
    dec     ch
    ret

na424657efade46718c69647b8b136ada:
    dd      nffc0538b4f324c81afe38ca637c660a5
    dd      n34d6e76f705c48dfbd4a26a016c9d0be
    cmp     al, 'V'
    ret

n14f738b864b640149d1fc8106b247666:
    dd      n6cf93a5a3aae44b1acec7c9cb5b8ebcd
    dd      n146aed7b5a37439ea848f58c5547e0f1
    cmp     ch, byte [106987224]
    ret

n9a57cecdb9824f73bceba06b3e041369:
    dd      n44b53204a9104067b9846f5451225afa
    dd      n3222e07d0c514015a6633261bd3365b1
    add     al, bl
    ret

nabbe5a10a1b4487fbe55d20aa5b0baa7:
    dd      n94d5cd843b3b4fe09642878b4b22d1c1
    dd      nfbd345dd595245c89cb9c4515cd7b64b
    mov     byte [8177002], ch
    ret

nb5b90beb057b4df0ae2746fc5794e1fc:
    dd      n0624375203a34924aab0af521605c94d
    dd      n89a2d3a1f2674c1c948605d5a531abf3
    mov     al, byte [password+3]
    ret

nb43d4880cf6043f3a72c16cfe2f193f2:
    dd      nddd040df65064f9f9e7ad5687601624f
    dd      n0042ce7382ee4cdfbbf04b03799d6917
    sub     word [105997084], di
    ret

n3d493b269d5d4c278644ea01200d32dd:
    dd      n937d6ed2501446f697e89efd6c7494f5
    dd      na367e6ebcd244100bcc900ff95ac3aa0
    cmp     di, word [83141534]
    ret

n780f39dbb260441790324532f52ff8ed:
    dd      ne85a7723726342109a861b342dd62b67
    dd      nce69d096231d45989160e5f54570ead0
    sub     ebx, dword [111787823]
    ret

n6e7e9901298842daaf2c566a1d878466:
    dd      n002b481fe6fb484fb99037f5a2e3d6a8
    dd      nf420c1a059b5498cbdff555595c6576f
    cmp     ax, 150
    ret

nc18db8e8188e470c8b00c00e981682de:
    dd      n300c285ed94a47ec9cd12614ae2de3fd
    dd      nd9b5c40a883847ca89becaf84d37a48f
    mov     ah, 35
    ret

n8ab7ade040014c39a0f87ef975938392:
    dd      n1e64eb2634ac4667b79882895e675339
    dd      n37a63955e76a4030a19655a7660d78fb
    cmp     bl, byte [48478637]
    ret

na0383f040b9d4615a9eaddd7509e8ff3:
    dd      neb1bc4f93bf64b85aed044d95342eff6
    dd      nd584ec595c604418b5e8cb1e77890931
    cmp     ch, 170
    ret

nb4028fa20e974454a9b038e0abf52c87:
    dd      n9351c0dce0244920b29057970f4a9674
    dd      nf31c0b02ac3c4c19bbea0895b2216014
    int     0x80
    ret

n36e9ac04f5614625ae5626d9288d5ee5:
    dd      nc328a807fe3c472da79dfefbd2040652
    dd      nca39ac269f7e42f19f197375bc83ddcc
    add     bh, 140
    ret

n4db4d5a4983748f5809dc0190b461640:
    dd      n8179f5a0fe6d4c6dac74ef378fb98991
    dd      n1773c162205f4acfb6f738ad293d7611
    add     dword [98610893], edx
    ret

n3b12a61cc0a44a8a8c7942921b41e1fb:
    dd      n00616bea27464bb393cb0bb001a81dfe
    dd      nbcdc253ea7534f158d056525d48924a4
    cmp     word [112796644], si
    ret

nff33a9e19452470f95e063004eb982b3:
    dd      n79a72970e5ba457aa1eab2b0b52e26d2
    dd      nc2c48b7e31a74a2dbe4db6fcdcbe0c3a
    mov     dword [53660399], edi
    ret

na2bfe19e542e4f649c1b73e924e1dd4f:
    dd      n754eb4d816de4bf283d7862780a915e9
    dd      n231e2dbe260549c985d0377f1d863ea9
    sub     edx, 137
    ret

n474371fa30b048048425b47821140c53:
    dd      n2b197406f91c4a98be6b961f67bf242a
    dd      ne99671391f654a65a995470855fecd05
    add     dword [36731686], ecx
    ret

nb4d7c40b60e14e4ca4fe3b201df2bfee:
    dd      ne7852ddf93324e5cb675b3394a5dfc5f
    dd      nb316b211c9454f07b29443e76003b8a3
    sub     cl, 182
    ret

n02f2b7867b3f45a2b8e2a021bbce484b:
    dd      neb1bc4f93bf64b85aed044d95342eff6
    dd      nbef41eb4929343d1a6a6d85e9d0fbee1
    mov     al, byte [password+1]
    ret

ne95b2c715a75459fb9068cf6decfede6:
    dd      n3fb113cf9b864d948b1d5b2efc27a693
    dd      n2ac793d5528d4a5486fdbd244fe6e56a
    add     al, byte [83836739]
    ret

n1b72b07c60dc4a5d99034bd8fea16e54:
    dd      n0a1d734cdbdd445284e466a5b10e0ce3
    dd      n0c808626718c466789a6c9165df0dca1
    inc     ax
    ret

n183702569a8c4b9ca9e70a11841c5207:
    dd      n821d386e73bd4e8a94aa9aca187c0b70
    dd      n4a99dcbaee334963b7f5b3e072f2bd4c
    dec     ch
    ret

n7e661504a1504134b69ccae812dcedd0:
    dd      n2b13f77ecea346c5ad19d65386f49f91
    dd      n6674960579c14637ac58bc5d107b55c5
    add     bx, word [17494141]
    ret

n1d55aa120bb44c8b859e33319dff93bf:
    dd      n3bdbd8950451478895c49391b75a2420
    dd      ne95b2c715a75459fb9068cf6decfede6
    sub     dx, 252
    ret

n1afb3f5a061448768dc04d60941d04de:
    dd      n0352ee27c2ee47819b00d5b3a4615bdd
    dd      n23b6aa6a11b545df9bf0262ee1ac11c1
    add     ax, word [126258294]
    ret

nf878827ca16a40158ab0070d7ccc3073:
    dd      nb50de4853455434b8ba9d6017fd2ee7d
    dd      n12a3720146034449a4fa945433b1729d
    cmp     al, 0x1c
    ret

nda918f9b0edc4951b65e2caec9f53911:
    dd      nb4028fa20e974454a9b038e0abf52c87
    dd      n85930114cb17467a87fddb779d87ad10
    cmp     word [85900582], di
    ret

n0d853fe95f274fef91ac20f556acc094:
    dd      nda82b1a578b54cb2ac2d9b78bd1ac130
    dd      ne0c6b4fbeb7e4d0989a47d968dff254d
    sub     esi, dword [12213357]
    ret

nd475c2bdcfa846b9954c6ccd367702fc:
    dd      n7a034e59451a47dabc3a9118adb3161a
    dd      n27e52df2ff6649c2b82397e76e6204c4
    inc     dh
    ret

n818a89cb7d8a4bfa917cfca7efa7c9a0:
    dd      ndf857523489e40c5981866829fcee4e7
    dd      n932699cc74fa486ebdb6f7495187dfb7
    sub     byte [75066657], dh
    ret

n937d6ed2501446f697e89efd6c7494f5:
    dd      n9a57cecdb9824f73bceba06b3e041369
    dd      nd4ce7ad1d78e4682b0b641331da0a6ca
    sub     cl, byte [120787605]
    ret

nc328a807fe3c472da79dfefbd2040652:
    dd      nf4cc94a4b239462f8ff7199a2981a736
    dd      n85930114cb17467a87fddb779d87ad10
    cmp     dword [112726357], edx
    ret

nc57bed5bb9804337ad572d6aed59f5da:
    dd      n4cec7cc36ef149c48ee5107f8c3d7ead
    dd      n46fa6e7590bf4a979a3040be77ab1f1d
    cmp     word [2971662], bx
    ret

nacce8e8728df46b494499e28c8c426bb:
    dd      n665b80eefd7342faa665b5848669393f
    dd      n4cde16b6cd544de98795772b18b6b481
    sub     ax, word [26149152]
    ret

nfd4c80c91c524e83ba86a0f69c4c2657:
    dd      nf878827ca16a40158ab0070d7ccc3073
    dd      n17886d0d3390472b8fa628c914d3f57a
    cmp     dword [91396080], edx
    ret

n2b13f77ecea346c5ad19d65386f49f91:
    dd      n615937b487284529919bcdbe1d2c0c92
    dd      n46fa6e7590bf4a979a3040be77ab1f1d
    mov     eax, 1
    ret

nf7698fe0e9e349d8ada5aad4c737ab5d:
    dd      ne28ce39ac8554c14a689cc85f23bb0f4
    dd      n1cd3d63248174c529e65c182e05d4ebd
    add     ebx, dword [9492769]
    ret

n4a3c18da62b9466ea037138ab61d05ef:
    dd      n03ef5b48ae414027992ae823f77c0cff
    dd      n2aff6ac8c89d484daef853fdf57afcc4
    xor     al, bl
    ret

n84692e4e68724ac4a3b1e8f555bcb444:
    dd      n7203cdd905f64884969bc77f31c2ecf7
    dd      n6c20c1a9869d4de2b5d5be0fdcb5d51e
    add     ah, byte [36607866]
    ret

ne73c5703034749aca069f1b4e86992ca:
    dd      n0a1d734cdbdd445284e466a5b10e0ce3
    dd      na424657efade46718c69647b8b136ada
    cmp     byte [13990719], bl
    ret

n1797b60b3b044ad987db2a34fb20bd75:
    dd      n93698713774c402b87f6bf7b3690a2dd
    dd      nd7b9cbd318d34fa688beade21a94cb01
    sub     dx, 77
    ret

naa2222d5b63e4308a9e5615d2f9cc9e2:
    dd      n1e056c39fcc04f8f94a7c7ba4b5ae6d8
    dd      n06cb9599a24d4623a2120542f6fa0b48
    dec     bx
    ret

nda82b1a578b54cb2ac2d9b78bd1ac130:
    dd      n9a57cecdb9824f73bceba06b3e041369
    dd      nca39ac269f7e42f19f197375bc83ddcc
    xor     bl, cl
    ret

n52ae5a262d1041288ccf9a05b03a5ebe:
    dd      n89a7a87978274ce4bb01bedf95ec20b7
    dd      n466502ecfc1b4264a50d7aa039d6288d
    dec     al
    ret

ne99671391f654a65a995470855fecd05:
    dd      nc3b4d643c88746c6a5e01ee9b1f6d433
    dd      n049023eb4ca14549a0478d228163a0c6
    sub     dword [94627407], edx
    ret

n416ff2c2a94f42c1be6a02af24c04159:
    dd      n9dab7aff955b46e09e283e3cd4125a10
    dd      n3bda26cdb1834182b6720e99550d1787
    sub     ax, 195
    ret

n615937b487284529919bcdbe1d2c0c92:
    dd      n5b520798b98f43e3af07313297b1da14
    dd      n1afb3f5a061448768dc04d60941d04de
    dec     si
    ret

n5d7d60d2707049d78489b690419483c0:
    dd      n002b481fe6fb484fb99037f5a2e3d6a8
    dd      n65d42bad64eb4f60ad8a65e8ffef6d8c
    dec     edi
    ret

nddd040df65064f9f9e7ad5687601624f:
    dd      n0c9b060d635b4cd288f38e788d02cf03
    dd      nf716cc477d4146d5a43fe814d7176d46
    jnz     wrong
    ret

n466522d5d73e4ff39cf2185020a38c0a:
    dd      n3b12a61cc0a44a8a8c7942921b41e1fb
    dd      n71b45a671f724855acaa8e1cd983f074
    sub     di, 59
    ret

n5af2a30b9c9c4d7797af2fd5fa6d4d1e:
    dd      n0dc55db67785471aad7e4b55f775038a
    dd      n0042ce7382ee4cdfbbf04b03799d6917
    cmp     al, 0x5b
    ret

nd0e4d1612d29459ba6d877eae9bc34f6:
    dd      n998b047ea4b541e1ae1ff74907433cdb
    dd      n665274ac5fa747d584b135067f840c8f
    inc     edx
    ret

n1ea2ab7f97e24b0fadcebb67f95812ff:
    dd      n683c40c8e54b471ea460f7db225b0546
    dd      nd896a85d040544d5ab6d057fff5e342d
    add     dx, word [66288138]
    ret

n3095ff3278b64557a17d1961c19a09ea:
    dd      nddaf32feafd74be2a5429c8efc8e0ffb
    dd      start
    add     si, word [41306532]
    ret

nd896a85d040544d5ab6d057fff5e342d:
    dd      n0d6c9e09e1684adbb2e0f01a5e593c00
    dd      nb632684b1f6341f6813a0802d95923e4
    cmp     dword [50122442], ecx
    ret

n0c9b060d635b4cd288f38e788d02cf03:
    dd      nc44f1788251043e0ae559d086941fd4a
    dd      n0a1d734cdbdd445284e466a5b10e0ce3
    mov     al, byte [password+12]
    ret

n754eb4d816de4bf283d7862780a915e9:
    dd      nb4028fa20e974454a9b038e0abf52c87
    dd      n94d5cd843b3b4fe09642878b4b22d1c1
    sub     byte [96317133], ch
    ret

n994e10e8a0854f6ba1ae23dbba779e6b:
    dd      ncbf85b0b9ca64479a4232f2cbf28f96e
    dd      nf7698fe0e9e349d8ada5aad4c737ab5d
    inc     bh
    ret

n300c285ed94a47ec9cd12614ae2de3fd:
    dd      n1a2f998edd8a4d09b274f4154b1ca21d
    dd      nb7e2ec18e52e4bb2b63b16fd868c6523
    add     word [124486552], cx
    ret

n7e8326cd5f134546b9b5b664f4d25e5d:
    dd      nd92b308cfcdf42a9892f0a9f96dcb870
    dd      nd55edcb0a6af41daac76f764ca4d1e08
    dec     si
    ret

nafd3c3e0b1f74b82bcc1d0a25f8915ac:
    dd      n9d5f73eb574549f9aead6d50853a92a5
    dd      n6716398583314a56a2bcb01f1637d33e
    cmp     edi, dword [10027688]
    ret

n321f0ee6c9864693bf1ed9f5cd77c68f:
    dd      n1ffbc7474ffb426ca04e589f7f96ecb4
    dd      n9f98ad0f7a1a4a0c8ad2f5d26b2543cb
    sub     bx, word [31310028]
    ret

n2209c5a15d084d7db92885414bab7791:
    dd      n4a3c18da62b9466ea037138ab61d05ef
    dd      nf9145cb0b4de4acbbfa7bd07f5018fa6
    and     bl, 0x53
    ret

ndaddf96096c1447ca11fc034148735ba:
    dd      na2bfe19e542e4f649c1b73e924e1dd4f
    dd      n3be4e9a16938459a89e0b5102df643f6
    sub     word [72647700], ax
    ret

na3602b20048645e4b7f280b815e5be2e:
    dd      n9b4434d551ff46aa8a10d689d3cfe93e
    dd      n880635899a114bf1b7bae4af840d68ac
    mov     edx, 13
    ret

n2e31c92b141e41b0bbfa521d916eece2:
    dd      nc452026c1f6a49bab3dbd76554f540b4
    dd      nb51e6c3001e04203930c9174f0a7d90b
    dec     bh
    ret

n1a91488d469f428abe38c183fca0de1d:
    dd      n75832cdd7450497394ed76ff23cfd623
    dd      nbe1b39b536254d3095a0c469a4a21a61
    inc     eax
    ret

n8b9a75d68d4e4fdcb4c70bc3e2869737:
    dd      ne28ce39ac8554c14a689cc85f23bb0f4
    dd      nb7f4ec3980b44cf2afd447ec141bd3a0
    dec     cx
    ret

n708e1a42aaa34a55b992ba286b65bc75:
    dd      n665b80eefd7342faa665b5848669393f
    dd      n002b481fe6fb484fb99037f5a2e3d6a8
    inc     dl
    ret

nb8acb7da1297410bacc2ccaef3adb2c3:
    dd      n3be4e9a16938459a89e0b5102df643f6
    dd      n980009e26cf84291bb93eca3ca8be806
    mov     byte [53984418], bl
    ret

nc8f486de6ff641d79b43dd03d7116161:
    dd      n3e88a737c7c9425db4684acdb9bf804d
    dd      n9a57cecdb9824f73bceba06b3e041369
    sub     dword [54510028], esi
    ret

n7b7e325ccb254cb9a31160b7d121f728:
    dd      n1e64eb2634ac4667b79882895e675339
    dd      n85c22a9cfdb24dc383b9928ebe98464e
    cmp     byte [85221929], cl
    ret

n597711df0d424df687d58e5533aba8e6:
    dd      n3e3d7547302844cd8b9487fe8ad1a564
    dd      n821d386e73bd4e8a94aa9aca187c0b70
    dec     cl
    ret

n0b0e639acb7e43f3a6b47a38207bf9e7:
    dd      n6ec324cbacb2493eb80bd97ab71572a4
    dd      n075b5f0584b241b7a6dc43e7564e21c2
    dec     cx
    ret

nd7baf9cb766949d1a4a79d5b148df0e5:
    dd      n85c22a9cfdb24dc383b9928ebe98464e
    dd      nd0e4d1612d29459ba6d877eae9bc34f6
    mov     byte [19142482], ch
    ret

nf79fb368b600466f9fe4d4db3a4737da:
    dd      n474a3ff929464d3990ededd90a159479
    dd      na32f178dfe09492a9d635c8bf29bb07c
    inc     edi
    ret

nbbda85c59dc14d2b95d7a9655bb8e3d4:
    dd      n48154172937f411b8964c9ee9dcc546a
    dd      n09319cad14c84d35a800235de03b10f1
    mov     al, byte [password+11]
    ret

n89a7a87978274ce4bb01bedf95ec20b7:
    dd      nb65327ad1e834f70ad788539f94c9c34
    dd      ne28ce39ac8554c14a689cc85f23bb0f4
    mov     dl, 19
    ret

n50d8e9abacfa41f2bd8c73ce44ccbf53:
    dd      ne1d743464bc84cd4b2c7311fb98eb254
    dd      n8961c339142a4fbdb5818f4c6589136f
    xor     al, byte [password+2]
    ret

n76bba4a5b17940ee90d80c8f8893ca7d:
    dd      n4b3f95fe70644aff960f49861088391e
    dd      n6e3b7aa03a9845f3b72a9ab1f6166aac
    sub     bx, word [125135681]
    ret

nc5cff251ef6642258df4c2113aa3f6a3:
    dd      nd475c2bdcfa846b9954c6ccd367702fc
    dd      naa2222d5b63e4308a9e5615d2f9cc9e2
    sub     word [49690609], dx
    ret

n00616bea27464bb393cb0bb001a81dfe:
    dd      n002b481fe6fb484fb99037f5a2e3d6a8
    dd      na32f178dfe09492a9d635c8bf29bb07c
    cmp     dword [91071985], eax
    ret

nfeaeeef9ba3e4d9695082447c17b8e74:
    dd      ne85a7723726342109a861b342dd62b67
    dd      n213aa6d4059c4a008ee109d6eee8f87e
    sub     word [9898764], di
    ret

n02090a12e2db4d77bd753622c78a2b33:
    dd      na43c07a43b554471ab233ad8a42a0e22
    dd      n8dc4b39c8e174c31ad371c471d40a657
    jne     wrong
    ret

n474a3ff929464d3990ededd90a159479:
    dd      n75832cdd7450497394ed76ff23cfd623
    dd      n3d11fd72da04432fbd60b415a96824a6
    sub     ch, byte [39689860]
    ret

n99f24fa864ee40f68254432c94a48c3e:
    dd      n7a034e59451a47dabc3a9118adb3161a
    dd      nf737d25b2be641cabb9cbbd05752708e
    add     edi, 139
    ret

n0dfc86b9b8e6439a8f73541de492c31b:
    dd      n84692e4e68724ac4a3b1e8f555bcb444
    dd      n466522d5d73e4ff39cf2185020a38c0a
    dec     esi
    ret

ndc371b0c5f4a4fc88dffab8f61a9b730:
    dd      nf878827ca16a40158ab0070d7ccc3073
    dd      n4ea0c1362ca5448193daeead0d04b9fb
    sub     al, byte [password]
    ret

na56fb1cc2d0c4d9ba6595ddfd62cd537:
    dd      n73087da804774be09608e8026f9e966d
    dd      n2e7a463f43cd4b7eb0ae0b1d80b8105d
    jne     wrong
    ret

nb5bc67a9e7794feeb718e000301f5d14:
    dd      nbd416d5fdc124497b7b87193f9109893
    dd      n5fbec9ac907d4e2aa95ea291e9b6ddbe
    dec     cx
    ret

n8bf4f6b1726a4ca49eaf926381dd9798:
    dd      n3bda26cdb1834182b6720e99550d1787
    dd      n2db441abebdc450386cb7ec4745f270a
    int     0x80
    ret

n5086ccea82464136bf668df67b7a5fce:
    dd      nd7cba4a2e5f1407aab2a889d7d880a4d
    dd      n54b317ee93104ae3b7877a4f725296c6
    xor     al, 0x91
    ret

nee928b82cd3a4c66ad43b6d6951a9872:
    dd      n63e4dff5950349d589859194b113b2dc
    dd      na890ca84908c479bb53b29ee50a8d4e6
    cmp     byte [71884684], cl
    ret

n665274ac5fa747d584b135067f840c8f:
    dd      nd896a85d040544d5ab6d057fff5e342d
    dd      n757a6b21bc8d49629510e95f20c01a2e
    cmp     di, word [4800023]
    ret

ndcc34715017342978642a081478d7e79:
    dd      n53c54afe020746a6a947892955670970
    dd      nf420c1a059b5498cbdff555595c6576f
    cmp     word [84469295], di
    ret

ne1fe1623fb374959bffeb9f38d19c4d6:
    dd      n474371fa30b048048425b47821140c53
    dd      n53c54afe020746a6a947892955670970
    dec     eax
    ret

n4dfca2fd8320477e82566685570d1549:
    dd      nbf13ef9fb9844f86b19576141994b442
    dd      n0e7141720e7f4d679f6da0d95c5483bd
    inc     dl
    ret

nd0ca3d7696234937aa141ba949d578ec:
    dd      n54b317ee93104ae3b7877a4f725296c6
    dd      n7e564f0ebd16445195a65891ef22f6c5
    cmp     edx, dword [63488060]
    ret

n6674960579c14637ac58bc5d107b55c5:
    dd      n6174e0f3a44949baa47d2f8c24e24f20
    dd      n821d386e73bd4e8a94aa9aca187c0b70
    inc     bl
    ret

nf9145cb0b4de4acbbfa7bd07f5018fa6:
    dd      nfc2a0cdae74a4a1f992bfa2618bb6b6c
    dd      ne1fe1623fb374959bffeb9f38d19c4d6
    cmp     dh, 47
    ret

nc4dc80dc7a7748a7935bc9ba9d913cb5:
    dd      na3602b20048645e4b7f280b815e5be2e
    dd      n506378ebd6794949a00143d85f84b17a
    jnz     set_wrong
    ret

n9282037f90bc4b7f80441b5cf1fd58c9:
    dd      nf3f9bd326c5f46cd9c6e7a56220369ca
    dd      n13ffafc1c45f49e9862a41037148e5a7
    correct:    db      'Correct! :-)', 10
    ret

n1f455765812947c88170728a89594cae:
    dd      n3d493b269d5d4c278644ea01200d32dd
    dd      n300c285ed94a47ec9cd12614ae2de3fd
    mov     ebx, 46
    ret

nc44f1788251043e0ae559d086941fd4a:
    dd      na56fb1cc2d0c4d9ba6595ddfd62cd537
    dd      n506378ebd6794949a00143d85f84b17a
    cmp     al, byte [password+8]
    ret

n5680725b0d544f37bd73883ef80c7454:
    dd      n94d5cd843b3b4fe09642878b4b22d1c1
    dd      nd55edcb0a6af41daac76f764ca4d1e08
    dec     dx
    ret

n5b78de7665bf47ba9ec62700e237b770:
    dd      na367e6ebcd244100bcc900ff95ac3aa0
    dd      n3d493b269d5d4c278644ea01200d32dd
    dec     di
    ret

n4bd8f0a6da3f4094b33007f884d7dbd3:
    dd      nd7cba4a2e5f1407aab2a889d7d880a4d
    dd      nf8f97559219d437180f964b709b9a0a6
    sub     al, 'd'
    ret

n8dc4b39c8e174c31ad371c471d40a657:
    dd      n4712713825bd4d7996f96eb440ccd42b
    dd      n9866f2c82e32499b98e2410c75833496
    dec     bh
    ret

n94d5cd843b3b4fe09642878b4b22d1c1:
    dd      n1afb3f5a061448768dc04d60941d04de
    dd      n44ca1f2c6f364a09a070f7d3d2018991
    inc     dh
    ret

n2d034e0326254dec9962b5cf88076b3f:
    dd      n72e0bcc46b05403d93321e2f885bc680
    dd      n44ca1f2c6f364a09a070f7d3d2018991
    sub     word [60035679], di
    ret

n85c22a9cfdb24dc383b9928ebe98464e:
    dd      n85c22a9cfdb24dc383b9928ebe98464e
    dd      n1797b60b3b044ad987db2a34fb20bd75
    cmp     ebx, dword [80392710]
    ret

nf49716b112d64a8d9fb69476de8c7bca:
    dd      n998b047ea4b541e1ae1ff74907433cdb
    dd      n0bb1971f3c204f679e48ab9d626c8055
    dec     ah
    ret

ne391fd837e9b4b708dac1272afc64763:
    dd      n30042a0a43fb425796e7f431368498ee
    dd      nb8302ef780404cf1afa9254472dfd7d1
    cmp     word [31763719], ax
    ret

neeca4ee0e64f41f08ec0f13ffb7a1b76:
    dd      n1d29a98e7a8a45bc8f24e9278fce2c5e
    dd      nb64eec799e274ba0858474d679ff733d
    xor     al, bl
    ret

n435cf42334264eb4b8929ca1bd432487:
    dd      n46414d7e46814c28820dda907bb7a1ef
    dd      nf716cc477d4146d5a43fe814d7176d46
    dec     dh
    ret

n6acf4c25fe394ef08ac67e16edb8804e:
    dd      ne1fe1623fb374959bffeb9f38d19c4d6
    dd      nfc2a0cdae74a4a1f992bfa2618bb6b6c
    dec     cx
    ret

nea105b6bf99c437aa32d79e7d035e61f:
    dd      n84692e4e68724ac4a3b1e8f555bcb444
    dd      n8d9ce83285094cc9967ccedad8870242
    mov     word [129670512], ax
    ret

ndf857523489e40c5981866829fcee4e7:
    dd      n998b047ea4b541e1ae1ff74907433cdb
    dd      n23ffb80afc7240fcaec9263bec31019e
    inc     cl
    ret

na0815747fc284679892cb48887477fc1:
    dd      n44ca1f2c6f364a09a070f7d3d2018991
    dd      nede30d754b01405296288f067b649808
    sub     ah, 40
    ret

n06cb9599a24d4623a2120542f6fa0b48:
    dd      n36e9ac04f5614625ae5626d9288d5ee5
    dd      n46414d7e46814c28820dda907bb7a1ef
    sub     dword [12661996], eax
    ret

nd55b3ad21cf144c996de64da371b9765:
    dd      n2e204aeb77e646268b434d6fe3a0b7e1
    dd      nee928b82cd3a4c66ad43b6d6951a9872
    add     byte [34498587], dh
    ret

nad52ede8c51d4ab88a787f5110016da9:
    dd      n8755974bc5dd4c22aa4b2afa04bf3118
    dd      n0624375203a34924aab0af521605c94d
    dec     si
    ret

n3e3d7547302844cd8b9487fe8ad1a564:
    dd      n10c262302cc848b1a09ed67d0442a523
    dd      n5d9bd9a935984ebb8ea1ccfbf71dcf26
    sub     ebx, dword [108302430]
    ret

n571e2dd7314346918994f0786461e0da:
    dd      n9a8e9caceff44afca43e554b3db71fff
    dd      n77ae320a7dbf4447bca9976bad0666de
    dec     eax
    ret

n7e31bc20613f42fe961dc5b38a1936ff:
    dd      nd55b3ad21cf144c996de64da371b9765
    dd      n94f990aaa41848a890bff123a404ef29
    inc     ah
    ret

n360861f23f9a4a389e73538b9864b6fc:
    dd      n63e4dff5950349d589859194b113b2dc
    dd      n5af4f220065a42f98ee07aa63dcc7b90
    inc     bx
    ret

n0e1fce777db549cdb5b162fd058207f1:
    dd      nd7b9cbd318d34fa688beade21a94cb01
    dd      n064722e97de14fb58b79989a18573e10
    cmp     bx, word [133201059]
    ret

n13ffafc1c45f49e9862a41037148e5a7:
    dd      ndff91d3a72e640e8bf3eea772e28d8ae
    dd      n30042a0a43fb425796e7f431368498ee
    cmp     si, 53
    ret

n0df1cebbb2d6428588a89cb71cbe3daa:
    dd      na9a654ffa33447c995eceae05369bd90
    dd      n597711df0d424df687d58e5533aba8e6
    dec     dl
    ret

nf7e21a6350144d48a4f4128fe4dc0450:
    dd      n71b45a671f724855acaa8e1cd983f074
    dd      n1773c162205f4acfb6f738ad293d7611
    inc     si
    ret

n593974439a694ec9a41da67491df427c:
    dd      n7bd65bfcdadd4949ada66a2345ae9fcb
    dd      n89a2d3a1f2674c1c948605d5a531abf3
    add     word [26943808], cx
    ret

n03ef5b48ae414027992ae823f77c0cff:
    dd      n3095ff3278b64557a17d1961c19a09ea
    dd      n99bddece1f77486e821ffe97c672bca8
    inc     bx
    ret

n38fb10a412ed439ba7c8f722e54d4646:
    dd      nffe7c0690c3e400a9dee8b27613b7aed
    dd      nf7e21a6350144d48a4f4128fe4dc0450
    dec     ebx
    ret

n19c3cd605ff6432a95a6b9f5affd5939:
    dd      n09f97fcf2be8423fb7eac7e79924ebac
    dd      n466522d5d73e4ff39cf2185020a38c0a
    cmp     byte [117360467], cl
    ret

n53c54afe020746a6a947892955670970:
    dd      n44b53204a9104067b9846f5451225afa
    dd      n708e1a42aaa34a55b992ba286b65bc75
    add     word [65566379], ax
    ret

nbffcbfd0f9214d69a81b4f14af873302:
    dd      nc5cff251ef6642258df4c2113aa3f6a3
    dd      nfc2a0cdae74a4a1f992bfa2618bb6b6c
    add     dl, 217
    ret

n977e5c293d2f46bb91772215f8f95b3c:
    dd      n2e116b13467d47ae882f84ad7bcd898f
    dd      n125215488dc24b50b95b9f9f3f82409d
    sub     byte [28692708], dl
    ret

nb316b211c9454f07b29443e76003b8a3:
    dd      n9f98ad0f7a1a4a0c8ad2f5d26b2543cb
    dd      n801a4b3cdbfc4100916f0fcf83353a30
    dec     ebx
    ret

n38a2b2c7218b4eb6b2a1464eea5be47c:
    dd      n30042a0a43fb425796e7f431368498ee
    dd      n4b3f95fe70644aff960f49861088391e
    add     si, word [87655161]
    ret

n466502ecfc1b4264a50d7aa039d6288d:
    dd      n51724631270c43008a8b34a64db85d41
    dd      n9c39cfd1ae074758bfd9ce71512ca022
    cmp     al, byte [password+3]
    ret

n27e52df2ff6649c2b82397e76e6204c4:
    dd      na13aed1ba13e4f4d8849bcd6e30df1e2
    dd      nc3d704a127084de893121451b121fc40
    mov     ebx, dword [103661705]
    ret

nede30d754b01405296288f067b649808:
    dd      n5b78de7665bf47ba9ec62700e237b770
    dd      n2aaf1a265fbc4f97a7c28740e1670079
    mov     dword [68613547], edx
    ret

nb582d43b32b24e4baa337fb48afbe2ba:
    dd      n9833ad5165a64011874aa22c4291eb18
    dd      n0bdcecfad55b408899fb75e985d4a175
    mov     dword [125207311], edi
    ret

n621e3fbc6fb34509a61f1e40390ac910:
    dd      n65bc5c9678e848eb895175b52eaa2782
    dd      n9282037f90bc4b7f80441b5cf1fd58c9
    prompt:     db      'Enter the password: '
    ret

n7203cdd905f64884969bc77f31c2ecf7:
    dd      n03febc0048e3402ba36b4100f397d40e
    dd      n05d72dc1d1aa48258f927ac0651e510a
    mov     edx, dword [110818698]
    ret

nfa475c6491a6441989dff9f3ead3eace:
    dd      n729a33eb58b1465aa45362eefa6d0772
    dd      n3d493b269d5d4c278644ea01200d32dd
    mov     word [90410311], cx
    ret

n506378ebd6794949a00143d85f84b17a:
    dd      n474a3ff929464d3990ededd90a159479
    dd      n8ce61342d9444cc4982a7fca2c88976b
    inc     di
    ret

n2969a1c209354b0e9782709d2ea5b349:
    dd      n65d42bad64eb4f60ad8a65e8ffef6d8c
    dd      nc328a807fe3c472da79dfefbd2040652
    sub     si, 214
    ret

n9fb2dcb1fde44dcfa1af72a3c2a9b65e:
    dd      n50c35b6396794f369584b4b2c03a2412
    dd      nf567e0b66c9f460c868142eccd6994e3
    inc     bh
    ret

nd974e7f33bda4ec5b5ebef3724a21e09:
    dd      nec7891a2d33f44ef9d9067be0e79b515
    dd      nafd3c3e0b1f74b82bcc1d0a25f8915ac
    inc     cx
    ret

nc3b4d643c88746c6a5e01ee9b1f6d433:
    dd      n3e88a737c7c9425db4684acdb9bf804d
    dd      nb2cb450ead9a4368bb496f673487a0d7
    add     ax, word [53726292]
    ret

n118bc3fd95ee479a9c378c4581e0a24e:
    dd      n84692e4e68724ac4a3b1e8f555bcb444
    dd      nb50de4853455434b8ba9d6017fd2ee7d
    mov     edi, 177
    ret

n2833d968433941459af9669b5dd59c71:
    dd      n932699cc74fa486ebdb6f7495187dfb7
    dd      nee928b82cd3a4c66ad43b6d6951a9872
    dec     ah
    ret

n99c398ae21dc491caea0d7271cedadd2:
    dd      ncbf85b0b9ca64479a4232f2cbf28f96e
    dd      nb582d43b32b24e4baa337fb48afbe2ba
    dec     edi
    ret

nbda30450f16d4d428905360da1078329:
    dd      na0383f040b9d4615a9eaddd7509e8ff3
    dd      n8755974bc5dd4c22aa4b2afa04bf3118
    sub     byte [127954679], dl
    ret

ncbee7fa9cf5e405d9eedb1851f00aa95:
    dd      n4dfca2fd8320477e82566685570d1549
    dd      n4d37767f119a415ea7ab685d4f219b0d
    add     dword [113909638], ecx
    ret

n372b3dfb9b834363b0a4d58ad8bff2f0:
    dd      nb50de4853455434b8ba9d6017fd2ee7d
    dd      n1f455765812947c88170728a89594cae
    mov     bl, 213
    ret

nba025563875b48d7b86671ab4f856f01:
    dd      n1f455765812947c88170728a89594cae
    dd      n994e10e8a0854f6ba1ae23dbba779e6b
    add     esi, dword [40850969]
    ret

nf3535c22d8164bdc9260d26d955b1bca:
    dd      n6174e0f3a44949baa47d2f8c24e24f20
    dd      n0d6c9e09e1684adbb2e0f01a5e593c00
    dec     edi
    ret

n8ce61342d9444cc4982a7fca2c88976b:
    dd      n2b197406f91c4a98be6b961f67bf242a
    dd      n4bd8f0a6da3f4094b33007f884d7dbd3
    add     word [109278622], ax
    ret

ncc51d7df406740c1b8f508c35fe98b28:
    dd      ne4ca22c1effc400d8872adcaafdcb765
    dd      n4fa0736cb9db4534b37efce9549a5d77
    cmp     bh, byte [19849868]
    ret

n527f09a0a4394d09ac26efba580431ac:
    dd      nbd416d5fdc124497b7b87193f9109893
    dd      n315013e932ca4c33bd14169eba88741a
    inc     esi
    ret

nc186e74177e64b6b999ab06bd110641d:
    dd      nfa475c6491a6441989dff9f3ead3eace
    dd      n1451c64158694a05994d25ce70e6ca70
    inc     ch
    ret

n729a33eb58b1465aa45362eefa6d0772:
    dd      n14be4e4bb7284845a29d0ce2d2d9d912
    dd      n0e1fce777db549cdb5b162fd058207f1
    mov     bh, byte [24280032]
    ret

na6d1986cd8604b0485ba88916780d601:
    dd      n213aa6d4059c4a008ee109d6eee8f87e
    dd      na846af1c232748ba9529a6edd93ad359
    cmp     ah, 96
    ret

n864f5d4a538c45d191fd7ece6eb281fc:
    dd      n821d386e73bd4e8a94aa9aca187c0b70
    dd      n0c9b060d635b4cd288f38e788d02cf03
    cmp     dx, word [26331851]
    ret

n12a3720146034449a4fa945433b1729d:
    dd      ne85a7723726342109a861b342dd62b67
    dd      nd974e7f33bda4ec5b5ebef3724a21e09
    jne     wrong
    ret

n9304df8ed1bd466999ea3b4cf1f61b0b:
    dd      n629047d6711840669924c151ca0d8543
    dd      nd55edcb0a6af41daac76f764ca4d1e08
    mov     word [78408707], si
    ret

n8a844eb598e24548926ebfe56b03db68:
    dd      nfe8fdfbe7c574f79958a31102270ce4d
    dd      nd475c2bdcfa846b9954c6ccd367702fc
    mov     ebx, 1
    ret

n3be4e9a16938459a89e0b5102df643f6:
    dd      n4d37767f119a415ea7ab685d4f219b0d
    dd      n37910519e74c4702a0b360e7af7e078c
    sub     ecx, 93
    ret

n3d4a16c163b54f9096afd61c6e54c4a6:
    dd      n3f8d97f66ad64e46bc8c3c5c5f6464d8
    dd      n665274ac5fa747d584b135067f840c8f
    cmp     ah, 26
    ret

nd3974848b2a84d8991b59df790e20567:
    dd      n14f738b864b640149d1fc8106b247666
    dd      n241e74d22bd442c7a9a10662aa5480e9
    add     ax, 225
    ret

nef5717b316d54c0ca6b8d4fd90c35a02:
    dd      nc114c1b1696c4b22b48da53ca9dc7d42
    dd      n1451c64158694a05994d25ce70e6ca70
    dec     edi
    ret

na9fc582685b74060b6e99ba5cd378470:
    dd      nbd416d5fdc124497b7b87193f9109893
    dd      n729a33eb58b1465aa45362eefa6d0772
    inc     ebx
    ret

nbefde78b614341d8a18b3d2e00cd318e:
    dd      nb78350ff87cf40378f7155704443b2d7
    dd      nb62538f43b854d23988843fcdfe1f384
    add     dword [22533548], ebx
    ret

n0c808626718c466789a6c9165df0dca1:
    dd      n729a33eb58b1465aa45362eefa6d0772
    dd      n9dab7aff955b46e09e283e3cd4125a10
    mov     word [45036720], bx
    ret

n04d28298a93e42cab80d439adb9c790b:
    dd      n0d853fe95f274fef91ac20f556acc094
    dd      n27beb4c16c144e94b6dec287731a2ff2
    add     dword [105424212], esi
    ret

n08430aa944914df49f2244aba02bd86c:
    dd      n8755974bc5dd4c22aa4b2afa04bf3118
    dd      nbffcbfd0f9214d69a81b4f14af873302
    inc     si
    ret

n012dd202b8124447b5f3106bcbdf6200:
    dd      n1bbbd54f456142199ff81692e3252024
    dd      n666fa0c3e7ae488b99cd04b9f5707223
    inc     bh
    ret

nc114c1b1696c4b22b48da53ca9dc7d42:
    dd      n2b197406f91c4a98be6b961f67bf242a
    dd      nd3d1fb0b7dfb436186db40f976382d2a
    cmp     dword [15876021], edx
    ret

ndc98ae68464f407eb2f3ca5f14383316:
    dd      nf716cc477d4146d5a43fe814d7176d46
    dd      n94d5cd843b3b4fe09642878b4b22d1c1
    sub     al, byte [97458083]
    ret

neb1bc4f93bf64b85aed044d95342eff6:
    dd      n8179f5a0fe6d4c6dac74ef378fb98991
    dd      n8ab7ade040014c39a0f87ef975938392
    sub     si, 113
    ret

nf567e0b66c9f460c868142eccd6994e3:
    dd      nef5717b316d54c0ca6b8d4fd90c35a02
    dd      ndc371b0c5f4a4fc88dffab8f61a9b730
    sub     byte [76561946], bh
    ret

n2e204aeb77e646268b434d6fe3a0b7e1:
    dd      nb62538f43b854d23988843fcdfe1f384
    dd      n0d853fe95f274fef91ac20f556acc094
    dec     dl
    ret

n2aff6ac8c89d484daef853fdf57afcc4:
    dd      n59bffc56972342478b322ec200f72e74
    dd      n4cde16b6cd544de98795772b18b6b481
    cmp     al, 0x65
    ret

nebe09819e4514613819b7ddeb7c4caa0:
    dd      n2e7a463f43cd4b7eb0ae0b1d80b8105d
    dd      n416ff2c2a94f42c1be6a02af24c04159
    cmp     byte [78252751], dl
    ret

na85e0595fcfe4b5286a281ee22b6559c:
    dd      nd0e88f10eb4d49ffa98d1e0da6b7ef63
    dd      n0e7141720e7f4d679f6da0d95c5483bd
    sub     al, 0x03
    ret

nd4f0aa4fc3c843a5a1de5d648a108a75:
    dd      n20c4978632d5443ba5d7a45e1e530933
    dd      nc5cff251ef6642258df4c2113aa3f6a3
    sub     word [127994549], bx
    ret

nb632684b1f6341f6813a0802d95923e4:
    dd      ndf857523489e40c5981866829fcee4e7
    dd      nbbda85c59dc14d2b95d7a9655bb8e3d4
    jne     wrong
    ret

n98846aca46b9451cb9bea8c41ba39411:
    dd      n54b317ee93104ae3b7877a4f725296c6
    dd      n2e020de9c2ad41b193c6587afc39b40b
    mov     dword [88580861], ebx
    ret

ned7202b2825d4ebc9814b22d2cd9d932:
    dd      n864518d5da21446bb4488208e2a4c414
    dd      necafc0296689436687b46436058629ce
    jne     wrong
    ret

nbd68dbed410741479ae0474050346ef9:
    dd      n8ad89a1ecf574a858465f4e7f81093c6
    dd      n9282037f90bc4b7f80441b5cf1fd58c9
    sub     bh, byte [45601714]
    ret

nf75aea79bda447eca84044fd7f565e46:
    dd      ne73c5703034749aca069f1b4e86992ca
    dd      nee928b82cd3a4c66ad43b6d6951a9872
    cmp     word [101526571], si
    ret

n37910519e74c4702a0b360e7af7e078c:
    dd      n8179f5a0fe6d4c6dac74ef378fb98991
    dd      n8d85b96cea1447d38444ef5af62441da
    inc     ebx
    ret

nf60fb3f969b949cfac97bdd6a77ce1a0:
    dd      n37a63955e76a4030a19655a7660d78fb
    dd      nef286e8333f14ac5bf0f0ee8e4b8f9cf
    cmp     di, word [33857094]
    ret

n801a4b3cdbfc4100916f0fcf83353a30:
    dd      ne8d63aae50b1412b95e5f5d1af4b95b4
    dd      n52ae5a262d1041288ccf9a05b03a5ebe
    sub     word [21722558], si
    ret

nd55edcb0a6af41daac76f764ca4d1e08:
    dd      ndcc34715017342978642a081478d7e79
    dd      n593974439a694ec9a41da67491df427c
    dec     al
    ret

nc2ff2f03b0114af8a3f053024c707b53:
    dd      n2833d968433941459af9669b5dd59c71
    dd      nd41f5ab8d9d946989dbe7b7fd489b582
    dec     bl
    ret

n51a41bd3cfc04df8909260bf6583a678:
    dd      nb8e714736cc7478eaf0d66bd45db5be8
    dd      ne88d31955f4c4767ad636a679e1aa50e
    mov     eax, 4
    ret

n06a305311e834824b2c3e36d28d6c19c:
    dd      nc0a020f6b8c0404e88636253629172c3
    dd      n4a78061052ca4bfd9c6f1ced7805659d
    mov     bl, byte [password+3]
    ret

ne4ca22c1effc400d8872adcaafdcb765:
    dd      nb50de4853455434b8ba9d6017fd2ee7d
    dd      n6ec324cbacb2493eb80bd97ab71572a4
    inc     dx
    ret

n89fb381f1748438391e9bc963a8e7320:
    dd      n48154172937f411b8964c9ee9dcc546a
    dd      n665274ac5fa747d584b135067f840c8f
    sub     cl, 76
    ret

n716a79f3d69546adb7bc5b684434aae4:
    dd      n4cde16b6cd544de98795772b18b6b481
    dd      nf574803ad1124ff8af417be02e01651a
    xor     al, byte [password+5]
    ret

nc3fb6d9341414899a962f08c6ad86613:
    dd      n7e31bc20613f42fe961dc5b38a1936ff
    dd      nd3974848b2a84d8991b59df790e20567
    add     word [87894461], di
    ret

nbef41eb4929343d1a6a6d85e9d0fbee1:
    dd      n16906ee689564b8c965fdde853550a4a
    dd      n012dd202b8124447b5f3106bcbdf6200
    add     al, 0x20
    ret

n36acad7124b54538980d6d057d4ef951:
    dd      n8bf4f6b1726a4ca49eaf926381dd9798
    dd      nbf13ef9fb9844f86b19576141994b442
    mov     edx, 16
    ret

n9873f74173b549e5a47be72843fab944:
    dd      nebe09819e4514613819b7ddeb7c4caa0
    dd      n416ff2c2a94f42c1be6a02af24c04159
    dec     cl
    ret

n6cae7972f3d44f448606b9157207e058:
    dd      n11840b18effb4282ba1fe11abe59ba18
    dd      n73f074b682f144189130234cb394d68d
    inc     dh
    ret

nf6e627d9ef63425b802e2649598dc8b9:
    dd      n3d493b269d5d4c278644ea01200d32dd
    dd      nf75aea79bda447eca84044fd7f565e46
    sub     dl, 210
    ret

ndff91d3a72e640e8bf3eea772e28d8ae:
    dd      n39a5b81fb07e48999cc7ec94e692fff2
    dd      n46fa6e7590bf4a979a3040be77ab1f1d
    cmp     word [39178660], si
    ret

n9fb8b51acfa64fc28f77e8bfd3ea3464:
    dd      nd97ea5ef0f03412799b99b78890010e5
    dd      na13aed1ba13e4f4d8849bcd6e30df1e2
    cmp     al, al
    ret

n50c35b6396794f369584b4b2c03a2412:
    dd      n67a1fd7364654cc0869537addb79a9f2
    dd      n3d493b269d5d4c278644ea01200d32dd
    cmp     ebx, 147
    ret

n315013e932ca4c33bd14169eba88741a:
    dd      n1e056c39fcc04f8f94a7c7ba4b5ae6d8
    dd      nfbd345dd595245c89cb9c4515cd7b64b
    add     byte [77267821], ah
    ret

n1bbbd54f456142199ff81692e3252024:
    dd      nda5d3d732757443d9c5fdecbb07be84c
    dd      ncbf85b0b9ca64479a4232f2cbf28f96e
    mov     dword [2940338], ecx
    ret

n46414d7e46814c28820dda907bb7a1ef:
    dd      nd0ca3d7696234937aa141ba949d578ec
    dd      n106bb5361957471fab96d942ced3954e
    mov     word [113853703], ax
    ret

n6185e8bf6d324cd6b8109adbe1c31cfb:
    dd      n1afb3f5a061448768dc04d60941d04de
    dd      n5daddf94668541d3ae8c1061a91851f8
    inc     ecx
    ret

action:
            dd      exit
times 34    dd      0

node:       dd      start

eax_s:      dd      0
ebx_s:      dd      0
ecx_s:      dd      0
edx_s:      dd      0
flags_s:    dd      0

_start:
    ; Avoid the need for multiple sections by makng everything RWX.
    ; mprotect($$ (start of section), 0x2000, 7 (RWX))
    mov     eax, 125
    mov     ebx, $$
    mov     ecx, 0x2000
    mov     edx, 7
    int     0x80
    ; Call the main functions.
    call    sigaction
    call    main


sigaction:
    ; Exit gracefully on segfault.

    ; sigaction(11 (SIGSEGV), action (-> {exit, [], 0)}, NULL)
    mov     eax, 67
    mov     ebx, 11
    mov     ecx, action
    mov     edx, 0
    int     0x80

    ret


exit:
    ; Wait for children to die, then exit.

    ; waitpid(-1, NULL, 0)
    mov     eax, 7
    mov     ebx, -1
    mov     ecx, 0
    mov     edx, 0
    int     0x80
    ; if (ret >= 0) loop
    cmp     eax, 0
    jge     exit
    ; exit(0)
    mov     eax, 1
    mov     ebx, 0
    int     0x80


main:
    ; Call the current node and fork.
    ; Parent takes left, child right.

    call    call_node
    ; fork()
    mov     eax, 2
    int     0x80
    ; if (ret == 0) child
    test    eax, eax
    jz      main_child
main_parent:
    mov     eax, dword [node]
    mov     eax, dword [eax]
    mov     dword [node], eax
    jmp     main
main_child:
    mov     eax, dword [node]
    mov     eax, dword [eax+4]
    mov     dword [node], eax
    jmp     main


call_node:
    ; struct node {
    ;     left,
    ;     right,
    ;     instruction,
    ; }

    ; Get the address of the instruction.
    ; Must be done here so as not to mess with flags.
    mov     esi, dword [node]
    add     esi, 8

    ; Restore registers. Flag restoration feels hacky.
    xchg    dword [eax_s], eax
    xchg    dword [ebx_s], ebx
    xchg    dword [ecx_s], ecx
    xchg    dword [edx_s], edx
    pushfd
    pop     edi
    xchg    dword [flags_s], edi
    push    edi
    popfd

    ; Call the instruction.
    call    esi

    ; Restore registers. Flag restoration feels hacky.
    xchg    dword [eax_s], eax
    xchg    dword [ebx_s], ebx
    xchg    dword [ecx_s], ecx
    xchg    dword [edx_s], edx
    pushfd
    pop     edi
    xchg    dword [flags_s], edi
    push    edi
    popfd
    
    ret
; ELF footer.

filesize      equ     $ - $$
