import pandas as pd
import webbrowser


df = pd.read_csv('AppInfo - AppInfo.csv')

list = df["app_id"]

urlbase = "https://play.google.com/store/apps/details?id="


for app in list:
    webbrowser.open(urlbase + str(app), new=0, autoraise=True)
    result = input("Press Enter to continue to next app...")
