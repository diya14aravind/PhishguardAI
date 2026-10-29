"""Generate modern legitimate (ham) and promotional (spam) emails to balance the public datasets.

Why this exists: Enron ham is from 2001 and rarely contains links, while the phishing samples are recent and
almost always contain links. Without modern ham the model learns "has a link means phishing".
These rows are template based, so they teach the model the style of everyday mail. They are not a
replacement for real labelled mail. Replace or extend them with your own emails when you can.

Run:  python generate_modern_samples.py   (writes data/modern_synthetic.csv)
"""

import random

import pandas as pd

from phishguard.config import DATA_DIR

random.seed(7)

NAMES = ["Diya", "Arjun", "Meera", "Rahul", "Sneha", "Karthik", "Ananya", "Vikram", "Priya", "Rohan", "Isha", "Aman"]
SENDERS = ["Prof. Rao", "Dr. Nair", "Kavya", "Siddharth", "Neha", "the placement cell", "your team lead", "Ravi", "Sana"]
BRANDS = ["Amazon", "Flipkart", "Myntra", "Swiggy", "Zomato", "BigBasket", "Nykaa", "Ajio", "Croma", "MakeMyTrip", "Uber", "Netflix", "Spotify"]
DOMAINS = ["amazon.in", "flipkart.com", "swiggy.com", "zomato.com", "myntra.com", "github.com", "linkedin.com", "vit.ac.in",
           "google.com", "microsoft.com", "zoom.us", "notion.so", "canva.com", "coursera.org", "udemy.com"]
ITEMS = ["wireless mouse", "running shoes", "phone case", "notebook set", "backpack", "water bottle", "headphones",
         "desk lamp", "USB hub", "kurta", "textbook", "keyboard", "t-shirt", "laptop stand"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
TIMES = ["10 am", "11:30 am", "2 pm", "3:30 pm", "4 pm", "5 pm"]
PLACES = ["seminar hall", "library meeting room", "lab 3", "the cafeteria", "room 204", "the main auditorium"]
COURSES = ["Operating Systems", "Machine Learning", "Compiler Design", "Data Structures", "Cloud Computing", "Network Security"]
PROJECTS = ["the capstone demo", "the hackathon submission", "the API module", "the review presentation", "the dataset cleanup"]


def link(domain=None):
    chosen = domain or random.choice(DOMAINS)
    path = random.choice(["", "/orders/" + str(random.randint(1000, 99999)), "/account", "/help", "/track/" + str(random.randint(100, 9999)),
                          "/notifications", "/jobs/" + str(random.randint(10, 999)), "/p/" + str(random.randint(1, 500))])
    return "https://www." + chosen + path


def maybe(text, chance=0.5):
    if random.random() < chance:
        return text
    return ""


def ham_order():
    brand = random.choice(BRANDS)
    item = random.choice(ITEMS)
    order = str(random.randint(100000, 999999))
    forms = [
        "Hi {n}, your {b} order #{o} for {i} has shipped and will arrive on {d}. Track your package: {l}",
        "Your {b} order #{o} has been delivered. We hope you enjoy your {i}. Rate your purchase: {l}",
        "Thanks for shopping with {b}. Order #{o} ({i}) is confirmed. View order details: {l}",
        "{b} receipt: payment of Rs {amt} received for order #{o}. Download your invoice at {l}",
        "Hello {n}, your return request for {i} (order #{o}) was approved. Refund of Rs {amt} will reach you in 5 to 7 days. Details: {l}",
    ]
    return random.choice(forms).format(n=random.choice(NAMES), b=brand, o=order, i=item, d=random.choice(DAYS),
                                       amt=random.randint(199, 9999), l=link(random.choice(DOMAINS)))


def ham_account():
    forms = [
        "Your verification code is {c}. It expires in 10 minutes. If you did not request it, you can ignore this message.",
        "{c} is your one time password for login. Do not share it with anyone.",
        "You requested a password reset for your {b} account. Use this link within one hour: {l}. If this was not you, no action is needed.",
        "Security alert: a new sign in to your {b} account from a Windows device in Bengaluru. If this was you, you do not need to do anything. Review activity: {l}",
        "Welcome to {b}, {n}! Your account is ready. Get started with the quick guide here: {l}",
        "Your {b} subscription renews on {d}. You can manage or cancel anytime in your account settings: {l}",
    ]
    return random.choice(forms).format(c=random.randint(100000, 999999), b=random.choice(BRANDS), l=link(), n=random.choice(NAMES), d=random.choice(DAYS))


def ham_work():
    forms = [
        "Hi {n}, the meeting for {p} is on {d} at {t} in {pl}. Please bring your latest notes. {s}",
        "Dear students, the {c} assignment deadline is extended to {d}. Submit through the portal as usual. Regards, {s}",
        "Hi {n}, thanks for applying. We would like to schedule an interview on {d} at {t} IST. Let me know if that works for you. Regards, {s}",
        "Reminder: {c} class tomorrow at {t} in {pl}. Slides are uploaded here: {l}",
        "{n}, I reviewed {p} and left a few comments in the shared document: {l}. Can we discuss on {d}?",
        "Hi team, quick update on {p}. The tests are passing and the deployment is planned for {d}. Please review the pull request: {l}",
        "Dear {n}, your internship offer letter is attached. Please sign and return it by {d}. Do reach out if you have questions. {s}",
        "Hi {n}, the {c} marks have been published on the student portal. Contact your faculty advisor for any clarification.",
        "You have a new notification on GitHub: {s} commented on your pull request. View it here: {l}",
        "Calendar invite: {p} sync on {d} at {t}. Join with Zoom: {l}",
    ]
    return random.choice(forms).format(n=random.choice(NAMES), p=random.choice(PROJECTS), d=random.choice(DAYS), t=random.choice(TIMES),
                                       pl=random.choice(PLACES), c=random.choice(COURSES), s=random.choice(SENDERS), l=link())


def ham_personal():
    forms = [
        "Hey {n}, are we still on for lunch on {d}? I will book a table near {pl}.",
        "Hi {n}, sending the notes from {c} as promised. Let me know if anything is unclear.",
        "Thanks for your help with {p}. I owe you a coffee!",
        "Hi, sharing the photos from the trip: {l}. Let me know which ones you want printed.",
        "Hey {n}, can you send me the link to the {c} reference book? I could not find it on the library site.",
        "Just checking if you received the files I sent yesterday. No rush, reply when free.",
    ]
    return random.choice(forms).format(n=random.choice(NAMES), d=random.choice(DAYS), pl=random.choice(PLACES), c=random.choice(COURSES),
                                       p=random.choice(PROJECTS), l=link())


def ham_bank():
    forms = [
        "Your account statement for the month is ready. Log in to the official app or website to view it. We never ask for your PIN or password by email.",
        "Rs {amt} was debited from your account ending {last} on {d}. If you did not make this transaction, call the number on the back of your card.",
        "Your credit card bill of Rs {amt} is due on {d}. Pay using the official mobile app or net banking.",
        "Transaction alert: Rs {amt} credited to your account ending {last}. Available balance is shown in the app.",
    ]
    return random.choice(forms).format(amt=random.randint(150, 49999), last=random.randint(1000, 9999), d=random.choice(DAYS))


def spam_promo():
    brand = random.choice(BRANDS)
    forms = [
        "{b} mega sale! Flat {p}% off on {i} and more. Use code SAVE{p}. Shop now: {l} Limited time only. Unsubscribe: {u}",
        "Weekend special: buy one get one free on {i}. Order now and enjoy free delivery. Offer ends {d}. {l} To stop receiving these emails click unsubscribe.",
        "Exclusive deal just for you, {n}! Up to {p}% off. Hurry, stocks are running out. Grab the offer: {l}",
        "Big Billion savings are here. Best price guaranteed on {i}. Click here to shop: {l}. You are receiving this because you subscribed. Unsubscribe: {u}",
        "Last chance! Your {p}% discount coupon expires tonight. Redeem now at {l} and save big on {i}.",
        "Festive offer: pay only Rs {amt} for {i}. No cost EMI available. Limited period deal, shop now {l}",
        "Get cashback up to Rs {amt} on your first order with {b}. Download the app and order now: {l}",
        "New arrivals are here! Flash sale on {i}, {p}% off for the next 24 hours. Tap to explore: {l}",
    ]
    return random.choice(forms).format(b=brand, p=random.choice([20, 30, 40, 50, 60, 70, 80]), i=random.choice(ITEMS), l=link(),
                                       u=link() + "/unsubscribe", n=random.choice(NAMES), d=random.choice(DAYS), amt=random.randint(99, 4999))


def spam_other():
    forms = [
        "Get a pre-approved personal loan of up to Rs {amt}00 in minutes. No documents needed. Apply now {l}",
        "Earn money from home! Work only 2 hours a day and make thousands. No experience required. Join today {l}",
        "Boost your website traffic and rank number one on Google. Our SEO packages start at just Rs {amt}. Reply for a free quote.",
        "Cheap pills, lowest prices, no prescription needed. Order online now and get free shipping.",
        "Invest in crypto and double your money in 7 days. Guaranteed returns. Join our exclusive group: {l}",
        "Win a free trip to Goa! Take our quick survey and enter the prize draw. {l}",
        "Lose 10 kg in 2 weeks with this miracle supplement. Order now, limited stock, 70% off today only.",
        "Online casino bonus: deposit Rs 500 and get Rs 5000 free. Play now {l}",
    ]
    return random.choice(forms).format(amt=random.randint(5, 99), l=link())


def build(count, makers):
    rows = []
    for _ in range(count):
        maker = random.choice(makers)
        text = maker()
        text = text + maybe(" Regards, " + random.choice(SENDERS), 0.15)
        rows.append(text)
    return rows


def main():
    ham = build(3200, [ham_order, ham_account, ham_work, ham_work, ham_personal, ham_bank])
    spam = build(2400, [spam_promo, spam_promo, spam_promo, spam_other])
    frame = pd.DataFrame({"text": ham + spam, "label": ["ham"] * len(ham) + ["spam"] * len(spam)})
    frame = frame.drop_duplicates(subset=["text"])
    DATA_DIR.mkdir(exist_ok=True)
    frame.to_csv(DATA_DIR / "modern_synthetic.csv", index=False)
    print("Wrote data/modern_synthetic.csv " + str(frame["label"].value_counts().to_dict()))


if __name__ == "__main__":
    main()
