---
title: "FlareOn9 Write-Ups"
date: 2023-01-04T13:54:33+07:00
draft: false
---

Hi friend, this year is my third year following Flare-on and is the first time i managed to solve all the challenges. I finished in 276th place as can be seen [here](https://twitter.com/aldityairfan/status/1585159006909526016).
For those of you who don't know what Flare-On is, you can read it [here](https://www.mandiant.com/resources/blog/announcing-ninth-flareon-challenge), is an annual reverse engineering CTF by Mandiant (formerly by FireEye).


![pic1](Snipaste_2022-10-26_13-43-54.jpg)


I'm not going to make write-up for challenge 1 because i don't think it's needed, let's jump to challenge 2.


### Challenge 2 - PixelPoker
```
readme.txt:

Welcome to PixelPoker ^_^, the pixel game that's sweeping the nation!

Your goal is simple: find the correct pixel and click it

Good luck!
```


![pic2](Snipaste_2022-11-26_13-51-01.jpg)


As we can read in readme.txt above, the goal of this challenge is to find the correct pixel, and from DIE result, this file was created with C/C++.


I played the app first to gather other information, and i found that we are only given 10 chances to choose the correct pixel, after 10 times clicking the wrong pixel, a message box popped up then the program closed after we click OK.


![pic3](Snipaste_2022-11-26_14-08-37.jpg)


I opened the EXE in Ghidra then look for where the message box is executed and found it on FUN_004012c0.

```cpp
uVar8 = (uint)(short)param_4;
uVar6 = (uint)sVar1;
if (DAT_00413298 == 10) {
    MessageBoxA((HWND)0x0,"Womp womp... :(","Please play again!",0);
    DestroyWindow(param_1);
}
```

I assumed that pixel checking is also in this function. After analyzing this function in Ghidra decompiler, i'm interested in the following code snippet:

```cpp
FUN_004017be(local_148,0x104,"PixelPoker (%d,%d) - #%d/%d",(int)(short)param_4,(int)sVar1,DAT_00413298,10);
SetWindowTextA(param_1,local_148);
```

Then look at the window text when the app running:

![pic4](Snipaste_2022-11-26_15-04-20.jpg)


Now i can assume about some of the variables in the above code snippet. *param_4* is coordinate X, *sVar1* is coordinate Y, and *DAT_00413298* is a counter.


Before counter-checking, the value of coordinates X and Y is copied to variables *uVar8* and *uVar6* :

```cpp
uVar8 = (uint)(short)param_4;
uVar6 = (uint)sVar1;
```

Let's rename *uVar8* to *coordinateX* and *uVar6* to *coordinateY* to make analysis easier.

```cpp
coordinateX = (uint)(short)param_4;
coordinateY = (uint)sVar1;
```

continuing the analysis i found out where the values of the X and Y coordinates were checked 

```cpp
if ((coordinateX == s_FLARE-On_00412004._0_4_ % DAT_00413280) && (coordinateY == s_FLARE-On_00412004._4_4_ % DAT_00413284)){
    // snippet ................
}
```

Ghidra recognized the data at address 0x412004 is a string "FLARE-on", look in the assembly instruction, that string will be accessed as 2 DWORD named *s_FLARE-On_00412004._0_4_* and *s_FLARE-On_00412004._4_4_*. The first DWORD is 0x52414C46 ("FLAR") and the second DWORD is 0x6E4F2D45 ("E-0n"). Now i just need to find out the value of DAT_00413280 and DAT_00413284, and because these variables are initiated in runtime, my lazy approach is using xdbg debugger.


DAT_00413280:
![pic5](Snipaste_2022-11-26_15-54-38.jpg)


DAT_00413284:
![pic6](Snipaste_2022-11-26_15-54-58.jpg)


So now the correct value for coordinate X is 0x52414C46 % 0x2E5 = 0x5F (95) and coordinate Y is 0x6E4F2D45 % 0x281 = 0x139 (313). Let's click pixel at 95,313 and here's the result:


![pic7](Snipaste_2022-11-26_17-05-45.jpg)


Gotcha!!! :)


### Challenge 3 - magic8ball

Here we are given an EXE made with C++ with some DLLs.

![pic3-1](Snipaste_2022-11-26_17-20-01.jpg)


I run the EXE to gather information about its behavior.

![pic3-2](Snipaste_2022-11-26_17-23-28.jpg)


I assume that this program asks for two kinds of input, arrow keys and a question string. I try to input random arrow keys and question string and the program's answer is popped up in the center of the ball.

![pic3-3](Snipaste_2022-11-26_17-30-58.jpg)


I opened Ghidra and find where is the program's answer string that i got is stored, then find its references. It brings me to FUN_004012b0.

```cpp
int __fastcall FUN_004012b0(int param_1)
{
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(char **)(param_1 + 0xc) = "\t\tIt is\n\tcertain";
  *(char **)(param_1 + 0x10) = "\t\tIt is\n\tdecidedly\n\t\t\tso";
  *(char **)(param_1 + 0x14) = "Without a\n\t\tdoubt";
  *(char **)(param_1 + 0x18) = "\t\tYes\n\tdefinitely";
  *(char **)(param_1 + 0x1c) = "\tYou may\n\trely on\n\t\t\tit";
  *(char **)(param_1 + 0x20) = "\tAs I see\n\t\tit, yes";
  *(char **)(param_1 + 0x24) = "Most likely";
  *(char **)(param_1 + 0x28) = "\tOutlook\n\t\tgood";
  *(char **)(param_1 + 0x2c) = "\n\t\t\tYes";
  *(char **)(param_1 + 0x30) = "Signs point\n\t\tto yes";
  *(char **)(param_1 + 0x34) = "Reply hazy,\n\ttry again";
  *(char **)(param_1 + 0x38) = "Ask again\n\t\tlater";
  *(char **)(param_1 + 0x3c) = "Better not\n\ttell you\n\t\tnow";
  *(char **)(param_1 + 0x40) = "\tCannot\t\n\tpredict\n\t\tnow";
  *(char **)(param_1 + 0x44) = "Concentrate\n\tand ask\n\t\tagain";
  *(char **)(param_1 + 0x48) = "Don\'t count\n\t\ton it";
  *(char **)(param_1 + 0x4c) = "My reply is\n\t\t\tno";
  *(char **)(param_1 + 0x50) = "My sources\n\t\t\tsay\n\t\t\tno";
  *(char **)(param_1 + 0x54) = "Outlook not\n\tso good";
  *(char **)(param_1 + 0x58) = "\t\tVery\n\tdoubtful";
  *(undefined4 *)(param_1 + 0xe0) = 0;
  *(undefined4 *)(param_1 + 0xf0) = 0;
  *(undefined4 *)(param_1 + 0xf4) = 0xf;
  *(undefined *)(param_1 + 0xe0) = 0;
  *(undefined4 *)(param_1 + 0xf8) = 0;
  *(undefined4 *)(param_1 + 0x108) = 0;
  *(undefined4 *)(param_1 + 0x10c) = 0xf;
  *(undefined *)(param_1 + 0xf8) = 0;
  *(undefined4 *)(param_1 + 0x110) = 0;
  *(undefined4 *)(param_1 + 0x120) = 0;
  *(undefined4 *)(param_1 + 0x124) = 0xf;
  *(undefined *)(param_1 + 0x110) = 0;
  *(undefined4 *)(param_1 + 0x128) = 0;
  *(undefined4 *)(param_1 + 0x138) = 0;
  *(undefined4 *)(param_1 + 0x13c) = 0xf;
  *(undefined *)(param_1 + 0x128) = 0;
  *(undefined4 *)(param_1 + 0x140) = 0;
  *(undefined4 *)(param_1 + 0x150) = 0;
  *(undefined4 *)(param_1 + 0x154) = 0xf;
  *(undefined *)(param_1 + 0x140) = 0;
  return param_1;
}
```

What the program does in this function is just initialize some components. So let's move to where FUN_004012b0 is called, it brings me to FUN_004027a0.

```cpp
undefined4 FUN_004027a0(void)
{
  char cVar1;
  void *_Dst;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined4 *unaff_ESI;
  undefined4 uVar5;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  
  _Dst = (void *)FUN_0040296d(0x174);
  if (_Dst == (void *)0x0) {
    DAT_00406090 = (char *)0x0;
  }
  else {
    memset(_Dst,0,0x174);
    DAT_00406090 = (char *)FUN_004012b0((int)_Dst);
  }
  uVar5 = 0;
  FUN_004018f0(&stack0xffffffe4,"Magic 8 Ball",(int *)0xc);
  uVar2 = FUN_00402090(DAT_00406090,(undefined4 *)&stack0xffffffe4,0x2fff0000,0x2fff0000,800,600);
  if ((char)uVar2 != '\0') {
    cVar1 = *DAT_00406090;
    while (cVar1 != '\0') {
      iVar3 = SDL_GetTicks();
      FUN_00401e50(DAT_00406090,unaff_ESI,uVar5,in_stack_ffffffe8,in_stack_ffffffec,in_stack_fffffff0);
      FUN_004024e0(DAT_00406090);
      FUN_004022a0((int)DAT_00406090);
      iVar4 = SDL_GetTicks();
      if (iVar4 - iVar3 < 0x10) {
        SDL_Delay(0x10 - (iVar4 - iVar3));
      }
      cVar1 = *DAT_00406090;
    }
  }
  FUN_004019f0((int)DAT_00406090);
  return 0;
}
```

Here's what i've got after doing some analysis:

```cpp
FUN_004018f0(&stack0xffffffe4,"Magic 8 Ball",(int *)0xc);                                           // set up the window text
FUN_00401e50(DAT_00406090,unaff_ESI,uVar5,in_stack_ffffffe8,in_stack_ffffffec,in_stack_fffffff0);   // GUI stuff
FUN_004024e0(DAT_00406090);                                                                         // i assume this one is handling or checking user input
FUN_004022a0((int)DAT_00406090);                                                                    // rendering stuff
```

The following snippet code is what made me suspect FUN_004024e0.

```cpp
void __fastcall FUN_004024e0(void *param_1)
{
    // ======================================================
    // snippet ==============================================
    // ======================================================
  if (*(char *)((int)param_1 + 0x159) != '\0') {
    uVar1 = *(uint *)((int)param_1 + 0x124);
    ppcVar4 = this;
    if (0xf < uVar1) {
      ppcVar4 = (char **)*this;
    }
    if (*(char *)ppcVar4 == 'L') {
      ppcVar4 = this;
      if (0xf < uVar1) {
        ppcVar4 = (char **)*this;
      }
      if (*(char *)((int)ppcVar4 + 1) == 'L') {
        ppcVar4 = this;
        if (0xf < uVar1) {
          ppcVar4 = (char **)*this;
        }
        if (*(char *)((int)ppcVar4 + 2) == 'U') {
          ppcVar4 = this;
          if (0xf < uVar1) {
            ppcVar4 = (char **)*this;
          }
          if (*(char *)((int)ppcVar4 + 3) == 'R') {
            ppcVar4 = this;
            if (0xf < uVar1) {
              ppcVar4 = (char **)*this;
            }
            if (*(char *)(ppcVar4 + 1) == 'U') {
              ppcVar4 = this;
              if (0xf < uVar1) {
                ppcVar4 = (char **)*this;
              }
              if (*(char *)((int)ppcVar4 + 5) == 'L') {
                ppcVar4 = this;
                if (0xf < uVar1) {
                  ppcVar4 = (char **)*this;
                }
                if (*(char *)((int)ppcVar4 + 6) == 'D') {
                  ppcVar4 = this;
                  if (0xf < uVar1) {
                    ppcVar4 = (char **)*this;
                  }
                  if (*(char *)((int)ppcVar4 + 7) == 'U') {
                    ppcVar4 = this;
                    if (0xf < uVar1) {
                      ppcVar4 = (char **)*this;
                    }
                    if (*(char *)(ppcVar4 + 2) == 'L') {
                      _Str1 = (undefined4 *)((int)param_1 + 0xf8);
                      if (0xf < *(uint *)((int)param_1 + 0x10c)) {
                        _Str1 = (undefined4 *)*_Str1;
                      }
                      iVar2 = strncmp((char *)_Str1,(char *)((int)param_1 + 0x5c),0xf);
                      if (iVar2 == 0) {
                        FUN_00401220(&stack0xffffffc0,this);
                        FUN_00401a10(param_1,in_stack_ffffffc0);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return;
}
```

As you can see, there are nested-if and strncmp() which can be assumed that the program tries to compare/check something here.  Let's jump to the debugger, set a breakpoint at the beginning of nested-if, then try to input something into the program. I will use "up, down, left, right" for arrow-keys input, and "how are you?" for question input.


Here's the result from my xdbg debugger when the program is hit the breakpoint:

![pic3-4](Snipaste_2022-11-26_21-19-25.jpg)


The disassembler's comment told me everything without having to step through the whole instructions. So what i've got here is that the nested-if is for checking arrow-keys input then strncmp() is for checking the question input. Every arrow-keys input will be recorded and translated into a character, "U" for up, "D" for down, "L" for left, and "R" for right, and if we look at nested-if, we can find out the correct arrow-keys input is L-L-U-R-U-L-D-U-L. Then the question input will compare it with string *"gimme flag pls?"* using strncmp().

I restart the program and then input everything that i got above.


![pic3-5](Snipaste_2022-11-26_21-42-05.jpg)


gotcha!!! :D


... *to be continue* ...