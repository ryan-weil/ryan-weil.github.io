---
layout: post
title:  "Agent Tesla [Part 1: Unpacking]"
date:   2024-02-27 16:46:24 +0200
categories: malware
---

## Introduction

Agent Tesla is a popular info stealer coded in C# that consistently makes lists as one of the most prevalent malware strains. In this post we will be looking at a sample of Agent Tesla that has been packed by a very popular crypter. I am currently not aware of the name of the particular crypter responsible, but the amount of samples I am seeing daily being packed by it is insane. Despite this, I've only found 3 other articles documenting this crypter([here](https://avsw.ru/component/content/article/analiz-semejstva-troyanov-agent-tesla?catid=9:avsoft-blog&Itemid=140), [here](https://infosecwriteups.com/unfolding-remcos-rat-4-9-2-pro-dfb3cb25bbd1) and [here](https://osamaellahi.medium.com/unfolding-agent-tesla-the-art-of-credentials-harvesting-f1a988cfd137)), but they are not very detailed, especially in explaining how to unpack the malware. The goal of this post is to explain how to unpack the final payload, starting from the beginning.

## First Stage

We begin by opening the initial file `[MD5:B89F6062D174E452D189EC4248AF489C]` in popular .NET decompilation tool dnSpy. We right click the assembly and select 'Go to Entry Point'. We take notice of the line 
`Application.Run(new DangNhap());`. This creates a new instance of a Windows Form. We click on the `DangNhap` part to navigate to the class. There, we see `this.InitializeComponent();` in the constructor. Again, we click on `InitializeComponent` to go to its code. Looking at the top of the method, nothing seems immediately suspicious. However, as we scroll down more we see something peculiar:

![Alt text](/images/at1/image1.png)

This code fetches a resource named `Lux3`. Next, it performs a decryption routine on the resource. Once the routine is done, it dynamically calls `Assembly.Load()` to load the newly decrypted module. After this, it gets the Type at index 9 in the assembly, and the method at index 3 from the aforementioned type. It splits the class variable 'Discart' (defined as `private string Discart = "62657A54_626C66";`) by the underscore delimeter and invokes the method passing both halves of the delimeted string and the string "Sync_Center".

We need to debug the code and follow execution into the new assembly. To do this, we will place a breakpoint on the line here by clicking to the left of it by the line number. We will then begin debugging by clicking the `Start` button at the top of the window.

![Alt text](/images/at1/image.png)

Once the breakpoint is hit, we can observe in the `Locals` pane all the local variables. If we take a look at the `kb` local variable we can see its value:

![Alt text](/images/at1/image-1.png)

Take note of the full path `DeclareTextBoxValue.QuickSort.trist` here, `DeclareTextBoxValue` is the assembly, `QuickSort` is the class, and `trist` is the method being called.

If we go to the Modules pane (select Debug->Windows->Modules to display this pane), this new module is visible:

![Alt text](/images/at1/image-2.png)

Double clicking on the `DeclareTextBoxValue` assembly will open the assembly in-memory in dnSpy. We can then navigate to the method `trist` like so:

![Alt text](/images/at1/image-3.png)

## Second/Third Stage

Upon arriving at the method in the second stage, it is immediately clear that it is much too obfuscated to read. We will need to deobfuscate the assembly. Let's try saving/dumping this new assembly so we have access on the disk to it. Right click the `DeclareTextBoxValue` module in the Modules pane and save it to the disk.

We will attempt to use popular .NET deobfuscation tool de4dot and hope that this takes care of the obfuscation.

![alt text](/images/at1/image-4.png)

This output looks promising. The next step is drag and drop the newly outputted DeclareTextBoxValue-cleaned.dll into dnSpy and navigate to that same method. Let's see how it looks now:

![alt text](/images/at1/image-5.png)

This is MUCH more readable. Let's break down what is going on here. Firstly, we see a call to `Thread.Sleep()` which delays execution for 17129 milliseconds. Then, a byte array is returned from a call to `Vu.smethod_0`. Navigating to this method shows that it is pulling the byte array from a resource named `Key0`:

![alt text](/images/at1/image-6.png)

Following this, the array is decompressed to an assembly. `QuickSort.smethod_4` is called which is simply a wrapper for Assembly.Load(). The type `ReactionDiffusionLib.ReactionVessel` is then extracted.

An instance is created of the type, and the method `CasualitySource` is invoked twice. In order to see what this method is actually doing, we're going to need to continue our debugging and get into that assembly. 

In order to do this, we will go back to the original obfuscated assembly in dnSpy that is currently loaded in memory. Since the code is obfuscated, it will be difficult to find the call to `Assembly.Load()`. What we will do instead is go into the library itself and put a breakpoint on every overload of `Assembly.Load()`.

![alt text](/images/at1/image-8.png)

![alt text](/images/at1/image-9.png)

Let's now resume execution. It will take a moment because of that `Thread.Sleep()` from earlier.

![alt text](/images/at1/image-10.png)

Nice, it hit one of our breakpoints. Let's step through and see what was loaded.

![alt text](/images/at1/image-11.png)

![alt text](/images/at1/image-12.png)

This assembly that was loaded here with the odd symbol as the name is actually part of DeepSea Obfuscator's resource encryption. In the screenshot of the decompiled output of DLL that de4dot cleaned, it decrypted the resource and removed that portion of the code. Thus, we can simply continue on to the next `Assembly.Load()` which should be the same as the first one in the de4dot-cleaned DLL (called on line 23).

![alt text](/images/at1/image-13.png)

Now this looks interesting. Let's step out of the function and see what was just loaded.

![alt text](/images/at1/image-14.png)

Aha! There is the assembly we saw before: `ReactionDiffusionLib`. Now, let's dump it so we can investigate. This assembly is obfuscated as well, so we'll run it through de4dot first. Afterwards, we can open the deobfuscated assembly and investigate it as well as the two methods it calls:

![alt text](/images/at1/image-15.png)

![alt text](/images/at1/image-16.png)

As we can observe above, `CasualitySource` takes a string and decodes it. This is called twice, once for each half of that string (`62657A54` and `626C66`) we saw in the beginning.

![alt text](/images/at1/image-17.png)

In the case of `SearchResult`, it decrypts a byte array using XOR operations.

Returning back to the previous module, we can see that after decoding those two strings it passes the first one (variable `bezT`) and `EscapedIRemotingFormatter` to function `QuickSort.LowestBreakIteration`.

![alt text](/images/at1/image-18.png)

This function reaches back into the stage one assembly and extracts a resource. The resource in this case is a bitmap named `bezT`.

![alt text](/images/at1/image-19.png)

Then, a function called `RestoreOriginalBitmap()` is called on the extracted bitmap. The point of this function is to trim off unnecessary information from the bitmap.

![alt text](/images/at1/image-20.png)

The result of this function is then passed to `SearchResult', which as we saw earlier is performs a decryption routine.

Finally, smethod_4 and smethod_3 are called on the decrypted "bitmap" (which is really the fourth stage payload)

![alt text](/images/at1/image-21.png)

Now that we have a complete understanding of the second and third stages, we will once again press the continue button so we can reach that last `Assembly.Load()` call.

![alt text](/images/at1/image-22.png)

Now, we step out of the function:

![alt text](/images/at1/image-23.png)

A new module named `Tyrone` (lol) has been loaded. At this point we can simply keep stepping until we end up in the module. This is a little bit annoying, but it pays off as well get here to the obfuscated equivalent of `smethod_3`:

![alt text](/images/at1/image-25.png)

## Fourth Stage

The method `oII69EjNpf` of class `fjjMqxMfW1UDxAHtaE` in namespace `hShDAuVOfCX6Pa3JR1` in the `Tyrone` module is about to be executed next. Let's beat it to the punch and put a breakpoint there so we can catch it when it executes.

![alt text](/images/at1/image-27.png)

Well, this is some gnarly looking decompiler output. Let's rely again on our friend de4dot and run the dumped module through it.

After doing that, loading the result in dnSpy and going back to the function we were just in, we are presented with this:

![alt text](/images/at1/image-28.png)

de4dot appears to have been able to partially remove the control flow flattening, but not decrypt the strings. I attempted to manually decrypt them using a de4dot feature which allows you to specify the string decryption function token, but that failed as well. The other option we could do is write our own string decryptor or de4dot plugin. However, this article is focused particularly on unpacking and something like that is a bit out of scope for what we are doing. Luckily for any of you curious readers, we will be writing a custom de4dot plugin in the next article! For now, we are unfortunately going to have to resort to manually debugging the rest of the code until we can extract the final stage payload.

But...it sure would be a shame to lose the unflattened control flow we gained from running the module through de4dot. That is when I had an idea. If we look back at figure 10, the method from Tyrone is called with null parameters. That means, we could make a tiny C# loader to execute the deobfuscated assembly and have the benefit of the improved control flow to make our debugging easier! Let's do it!

![alt text](/images/at1/image-30.png)

We will drag our compiled binary into dnSpy (making sure it's in the same directory as Tyrone-cleaned.dll) and throw a breakpoint on the `m.Invoke(null, null)` part and run it.

![alt text](/images/at1/image-31.png)

![alt text](/images/at1/image-32.png)

I have my breakpoints set on the class constructor and target function. Now let's finish this once and for all! Stepping all the way to the end of the constructor sets all the global variables like so:

![alt text](/images/at1/image-33.png)

Function `oII69EjNpf` starts off by getting the path of the current assembly 

![alt text](/images/at1/image-34.png)

![alt text](/images/at1/image-35.png)

![alt text](/images/at1/image-36.png)

Then it attempts to open a mutex `bncFrQuGyBTmIf`. If it succeeds, the process terminates. Otherwise, it will create the mutex.

![alt text](/images/at1/image-37.png)

![alt text](/images/at1/image-38.png)

![alt text](/images/at1/image-39.png)

![alt text](/images/at1/image-40.png)

![alt text](/images/at1/image-41.png)

There is an optional thread sleep that is executed depending on the configuration of the crypter. In this particular sample is is not executed.
 
![alt text](/images/at1/image-42.png)

![alt text](/images/at1/image-44.png)

![alt text](/images/at1/image-43.png)
 
There is another check to determine if the crypter should display a messagebox, which again this sample does not do.
  
![alt text](/images/at1/image-45.png)

![alt text](/images/at1/image-46.png)

Next, there another unperformed check exists which will attempt to elevate privileges if the file is not being ran as an admin. This code again is not triggered in this sample

![alt text](/images/at1/image-48.png)

![alt text](/images/at1/image-47.png)

Another configuration-based decision is the possibility to download and execute another file (which does not happen in this case.) 

![alt text](/images/at1/image-49.png)

![alt text](/images/at1/image-50.png)

The code then decides if it wants to copy to AppData for persistence, which it does not do.

![alt text](/images/at1/image-51.png)

However in the case that it does do that, it will change the copied file's ACL permissions to perserve itself like so:

![alt text](/images/at1/image-52.png)

Then, the final payload `8cLv8` is extracted from the resources and decrypted.

![alt text](/images/at1/image-53.png)

![alt text](/images/at1/image-54.png)

There is a final check which determines the execution type (Reflection or Process Hollowing)

![alt text](/images/at1/image-55.png)

At this point, the injection type used is irrelevant (although if you are curious in this case it does use process hollowing). Since the payload has already been decrypted, we can simply dump that byte array `fjjMqxMfW1UDxAHtaE.obLq1XEEqU` from the `static fields` pane in dnSpy.

Opening the dumped file in dnSpy confirms that it is indeed Agent Tesla

![alt text](/images/at1/image-56.png)

Stay tuned for part two where we will be removing Agent Tesla's control flow flattening by writing our own de4dot plugin!