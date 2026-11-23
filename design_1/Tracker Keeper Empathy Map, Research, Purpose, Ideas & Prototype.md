# Tracker Keeper: Empathy Map, Research, Purpose, Ideas & Prototype

*Project: Tracker Keeper ("The Anti Procrastination Station"), a desktop app with a due-date countdown and a Pomodoro study timer. Source: python\_1 / logic\_1 / figma\_1 in the DAE-6-Month-Project-Files repo.*

> Note: the empathy map below is a draft persona built from the research in section 2. Before you submit, spend 10 minutes asking two or three classmates the questions at the end of section 1 and swap in their real words where they differ.

## 1. Empathy Map

**User:** A student (high school, college or trade program) with several assignments due, who knows what needs doing but keeps starting late.

**Says**

- "I'll start after dinner."
- "I work better under pressure."
- "I didn't realize it was due that soon."
- "I just need one good block of time."

**Thinks**

- "I still have plenty of time." (until suddenly it isn't true)
- "If I can't do it perfectly, why start?"
- "Everyone else seems to have this figured out."
- "Studying like this isn't paying off anyway."

**Does**

- Checks phone, texts friends or cleans instead of starting.
- Keeps deadlines in their head or scattered across syllabi and apps.
- Waits until the last day, then works in one long, stressful push.
- Tries a timer or app for a few days, then drops it if it feels like extra work.

**Feels**

- Guilt and anxiety about falling behind.
- Overwhelmed by big tasks.
- Relief and a burst of motivation as the deadline gets close.
- Frustrated that willpower alone does not work.

**Pains**

- Deadlines feel abstract until they are hours away.
- Large tasks are hard to start.
- Stress, poor sleep and more procrastination feed each other.
- Too many tools to set up and maintain.

**Gains (what they want)**

- Seeing exactly how much time is left, at a glance.
- An easy way to start: press one button and work.
- Short focused sessions with real breaks.
- A feeling of progress and control.

**Questions to validate with 2-3 real users**

1. When did you last start an assignment later than you planned? What happened?
2. How do you track due dates right now?
3. What have you tried to stay focused, and why did you stop?

## 2. Documented Research (User and Market)

### Source 1: User research, The Conversation / University of Wollongong, "72% of students say they procrastinate"

URL: https://www.uow.edu.au/media/2026/72-of-students-say-they-procrastinate-heres-how-to-stay-ontrack.php

- A US study of more than 65,000 college students found procrastination is extremely common.
- Knowing you are behind is stressful, and procrastination can be a way to feel more in control.
- Breaking larger tasks into smaller chunks helps prevent procrastination.
- **Takeaway for Tracker Keeper:** show time left clearly and make tasks feel smaller (short work sessions).

### Source 2: User research, Times Higher Education (Oct 8, 2026), "Procrastination 'biggest issue' harming students' performance"

URL: https://www.timeshighereducation.com/node/745373

- A large study found students rank procrastination above anxiety, depression and money problems as a barrier to performance.
- It describes a feedback loop: procrastinating causes stress, stress hurts sleep, and poor sleep causes more procrastination.
- The researcher says time-management problems are a symptom of procrastination, not its cause, and that deadlines are a strong motivator for procrastinators.
- **Takeaway:** a plain planner is not enough. The app should lower the barrier to starting and keep deadlines visible.

### Source 3: Academic research, thesis summary on academic procrastination (core.ac.uk)

URL: https://core.ac.uk/download/479012914.pdf

- About 70% of university students consider themselves procrastinators, and roughly 50% do so consistently and problematically.
- Temporal Motivation Theory: motivation rises as deadlines approach and falls with delay and impulsiveness.
- Students, parents and professionals agreed on the role of deadlines, intermittent deadlines and reducing the negative emotions tied to a task.
- **Takeaway:** a visible countdown makes the deadline "close" earlier; short sessions reduce how heavy the task feels.

### Source 4: Market research, Forest (focus timer app)

URLs: https://apps.apple.com/au/app/forest-focus-for-productivity/id866450515 and https://clickup.com/learn/topic/productivity/tools/forest/

- Forest grows a virtual tree during a focus session; leaving the app early kills it. It reports 60 million users and costs a one-time $3.99-$5.99 on mobile.
- Reviewers say it works best if your main distraction is your phone, and that a basic Pomodoro timer is enough if you only need a countdown.
- App Store reviewers ask for a true focus-break-focus-break Pomodoro option.
- **Takeaway:** emotional stakes and progress tracking are popular, but Forest is phone-focused and does not center on deadlines. A desktop tool with deadline plus Pomodoro fills a gap.

### Source 5: Market research, NDSU Disability Services list of focus apps

URL: https://ndsu.edu/disabilityservices/assistive\_technology/apps\_to\_support\_students\_in\_higher\_ed/apps\_for\_focus

- Focus To-Do combines a Pomodoro timer with a to-do list, reminders, time tracking and customizable session and break lengths.
- Other listed apps focus on timed sessions and progress tracking.
- **Takeaway:** competitors usually do one of two things (timer or task list). Tracker Keeper keeps both in one small, simple window.

### Research summary

- Procrastination is very common among students and gets worse with stress.
- Visible deadlines and short, structured work sessions are the two most supported fixes.
- Existing apps are either phone-based and gamified or full task managers; few pair a live countdown with Pomodoro in a lightweight desktop app.

## 3. Purpose Statement

**Tracker Keeper is a desktop app that combines a live due-date countdown with a customizable Pomodoro study timer. It is being created to help students who put off assignments see how much time they have left and start working in focused sessions instead of waiting until the last day.**

(Checklist: what is being made = desktop countdown and Pomodoro app; why = to reduce procrastination and last-minute work; who = students.)

## 4. Three Brainstormed Ideas

### Idea 1: Countdown + Pomodoro (current Tracker Keeper 2.5)

One due date shown as a live timer (days, hours, minutes, seconds) that turns red when the date passes, plus a Pomodoro window with adjustable work, short break and long break lengths and number of sessions.

- Strength: simple, fast to start, already built in Python/Tkinter.
- Limit: only one due date at a time.

### Idea 2: Multi-deadline dashboard with auto-planned study sessions

Students add several assignments. The app lists them by urgency with color coding, then suggests how many Pomodoro sessions to do today to stay on track (for example, 6 sessions over 3 days).

- Strength: breaks big tasks into small chunks, which the research supports.
- Limit: more setup, so it needs a very fast "add assignment" flow.

### Idea 3: Focus Garden with streaks

Every completed Pomodoro adds a plant to a garden on the home screen; skipping days or quitting a session early leaves a gap. A weekly summary shows total focused time.

- Strength: gives progress and emotional stakes like Forest, but on desktop.
- Limit: could feel gimmicky if it gets in the way of the timer.

**Direction:** build on Idea 1 now, then add Idea 2 first (biggest research support) and Idea 3 as a motivation layer.

## 5. Conversational Prototype

This is a scripted dialogue between a student and Tracker Keeper that shows the purpose, the research and the product visual. It can be run as a chat flow in a tool such as Voiceflow, Figma or a simple slide-by-slide script.

### Visual representation of the product

For the visual, use the Figma export in the repo (figma\_1/Tracker Keeper.jpg) and these three screens, which match the working app:

```
SCREEN 1: LOGIN                SCREEN 2: HOME                 SCREEN 3: POMODORO
+----------------------+       +----------------------+       +----------------------+
|    Tracker Keeper    |       |   Welcome, student!  |       |   Study - Pomodoro   |
| Anti Procrastination |       |                      |       | Work min:      [25]  |
|       Station        |       |   3d 4h 12m 09s      |       | Short break:   [5]   |
| Username: [______]   |       |   (live countdown)   |       | Long break:    [15]  |
| Password: [______]   |       |                      |       | Sessions:      [4]   |
|      [ Login ]       |       | [ Set Due Date    ]  |       |  Work Session 1/4    |
|                      |       | [ Reset Timer     ]  |       |       24:31          |
|                      |       | [ Study (Pomodoro)]  |       | [Start][Stop][Close] |
|                      |       | [ Exit            ]  |       |                      |
+----------------------+       +----------------------+       +----------------------+
```

### Dialogue script

**Tracker Keeper:** Hi! I'm Tracker Keeper, the Anti Procrastination Station. Quick intro before we start.

**Purpose statement (shown on screen):** Tracker Keeper is a desktop app that combines a live due-date countdown with a customizable Pomodoro study timer. It is being created to help students who put off assignments see how much time they have left and start working in focused sessions instead of waiting until the last day.

**Student:** Why does something like this even matter?

**Tracker Keeper:** Research shows it is a real problem. A large US study of more than 65,000 college students found procrastination is extremely common, and a 2026 report found it ranks above anxiety and depression as a barrier to student performance. Deadlines are a strong motivator, and breaking work into smaller chunks helps. Popular apps like Forest and Focus To-Do cover part of this, but they are phone-based or built around task lists.

**Student:** Okay, what do I do?

**Tracker Keeper:** Log in, and you land on the home screen (Screen 2). Tap **Set Due Date** and type when your assignment is due, for example 2026-12-05 23:59:00. Now you can see exactly how much time is left, counting down every second. It turns red when the date has passed.

**Student:** I still don't want to start.

**Tracker Keeper:** Then don't plan the whole assignment. Tap **Study (Pomodoro)** (Screen 3). Pick 25 minutes of work, a 5-minute break and 4 sessions, then press **Start**. You only have to commit to the first 25 minutes.

**Student:** And when I finish?

**Tracker Keeper:** After each work session you get a break, and a longer break after the last one. Come back to the home screen any time to check your countdown.

**How the prototype meets the purpose statement**

| Purpose element | How Tracker Keeper delivers it |
| --- | --- |
| Live due-date countdown | Home screen timer updates every second |
| Focused sessions | Customizable Pomodoro (work, short break, long break, sessions) |
| Students who put things off | Low-effort start; one button to begin a work block |
| Not waiting until the last day | Seeing the countdown early plus small daily sessions |

### Next prototype steps

- Add the multi-deadline list (Idea 2) as a fourth screen.
- Test the script with two or three classmates and record their reactions on the empathy map.

## Appendix: FigJam Logic Flowchart (Tracker\_Keeper.jam)

This FigJam board maps the program logic of Tracker Keeper: start the program, show the welcome screen, log in, ask for or load the due date and time, compare it to the current time, and display the time remaining. The preview image of the board is below. A .jam file cannot be embedded in a document, so submit or share the original Tracker\_Keeper.jam alongside this doc.

&#91;image: Tracker Keeper FigJam logic flowchart (preview of Tracker\_Keeper.jam)\]
