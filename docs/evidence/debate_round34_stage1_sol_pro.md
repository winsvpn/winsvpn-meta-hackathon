# Stage 1 Submission: stage1_sol_pro

**Evaluating RTT data**

I can evaluate based on the RTT data. It looks like I'm considering a compromise with 24 selections, resulting in a staggering total of 46 ms for 24, 30 ms for 16, and 62 ms for 32. Over a 10-second measurement, the overhead is under 0.62%. I might want to time from the individual first write to avoid bias, and it’ll be important to synchronize the measurement start, staggering the starts and warmups.
