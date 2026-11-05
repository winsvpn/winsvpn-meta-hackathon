# Stage 2 Rebuttal: stage2_sol_pro

**Evaluating write processes**

I'm thinking through how blocking writes work. They can definitely make some progress, but the `OutputStream.write` contract can hold things up until all the data is processed or an exception occurs. It’s interesting to note that having 32 blocked threads doesn’t mean constant context switch thrashing. I need to measure performance and thread stats to get a clearer picture. Also, it’s good to remember that accounting for bytes can be misleading when talking about delivery and goodput.
