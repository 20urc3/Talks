# Part 1:

Since I was a kid I always loved computers. While growing up I often ask myself what would I have
done of my life if those fabulous machine didn't existed yet, and I pictured myself building all kind
of automation and machinery. 

In ancient Greece was a famous inventor named Hero of Alexandria, who spent his life experimenting 
with complex invention such as steam-powered device like the aeolipile. Some even attribute him the invention of the Wind wheel. He invented a multitude of device to automate simple task, from a vending machine to a wind-wheel operating organ; He was also involved in developing mechanism for theater including entirely mechanical play of almost ten minutes length powered by a binary-like system of ropes, knots, and simple machines.

Here is also illustrated an antic Greek mechanism call the Antikythera, that could predict the timing of solar eclipses but also reveal characteristics of those eclipses.

It appears clearly that the human desire to automate tasks isn't new, we always thrive to reduce the amount of annoying task or make easier complex ones.

For me, automation is a savant mix between cleverness and laziness. You can't operate one without the other, pure laziness would be giving up on the task and pure cleverness would be entirely hypothetical.

# Part 2: Automation thought process

While preparing this talk I realized that I wanted you, the audience, to gain something more valuable than a list of tools or a simple trick. So I tried to built a mindmap, a thought process, on how automation works for me. As you might have guess by now, I'm really lazy, despite not being the most clever. So Automation has always had an import place in my heart. 

My recipe for a good automation is the following: 
- First, you need to do the manual work. I know it's annoying, you don't want to do that, I don't want to do that, nobody wants to. Unfortunately, one can only gain experience and comprehension of a complex task by doing it entirely by oneself. Once you master the different components involved in realizing this task then you can start thinking of the automation.
- Second, the analysis. It rarely come out of nowhere, during the realization of the task you'd get some idea and if you don't have all of them by the end of it you could spend some time thinking about what you did and how you did it.
- Third: Tweaking your tools, putting things together, experimenting. That's where stuff get messy, that's where you face issue, how to scrap this website? how to store this db? In other word: how to make it work.
- Fourth: Refine your process. Once you run it a few time, identify the weak and the strong spot, try to take full advantage of the strength of your process and to improve and fix as much as you can your weaknesses.
- Fifth: Profit! Your whole mechanism is in place it's now time to run it and see how it perform against the real world.

# Part 3: Existing example

Here follows a few interesting example where research leverage tools, LLM, and task distribution to achieve profitable bug hunting.
- https://google.github.io/oss-fuzz/research/llms/target_generation/ 
- https://blog.vidocsecurity.com/blog/2022-summary-how-we-made-120k-bug-bounty-in-a-year/
- https://labs.detectify.com/ethical-hacking/hakluke-creating-the-perfect-bug-bounty-automation/


# Part 4: Show off
I decided to put in practice what I was preaching. I built a pipe to automate fuzzing interesting target, hoping to get a bounty or a nice bug out of it.

- My first step was to automate monitor bug bounty website and make my bot reporting to me every week a summary of new scope, new targets, or previously rewarded target that wasn't listed in my db before.
- Then I used a small tool I wrote called sekiryu which is a little python wrapper around Ghidra that allowed me to run automated binary analysis/decompilation 
- Then I feed that into my SAST/DAST pipeline, where I basically reproduced what we saw oss-fuzz was doing, automated harness generation for fuzzing and SAST scans.
- And finally I profited! There is other bugs waiting to be disclosed, but I already got a Denial of service in 7zip reported and rewarded by ZDI using this automated process!

# Part 5: Lesson learned
Automation is great but it is only the result of hard work and intense research. There is a slight difference between obsessing over automating a task that would not result in any gain of time and just make it easier to perform manually or integrated in a whole automation process. Like everything in life it's a matter of balance and you need to take the time to weight your choices before spending days or weeks implementing it. Automation is great, but it's like everything else, it's only as good as you are.

# Part 6: Wait, here is where we are now.
- list of tools
