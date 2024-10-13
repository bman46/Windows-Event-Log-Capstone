from bigxml import Parser, xml_handle_element
from datetime import datetime
from operator import attrgetter
import functools
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import re

# Convert XML to object:
@xml_handle_element("Events", "Event")
class win_event:
  def __init__(self, node):
    self.EventID = "-1"
    self.TimeCreated = 0
    self.Computer = "N/A"
    self.TargetUserName = "N/A"

  @xml_handle_element("System", "EventID")
  def handle_eventid(self, node):
    self.EventID = node.text
  @xml_handle_element("System", "Computer")
  def handle_event_computer(self, node):
    self.Computer = node.text
  @xml_handle_element("EventData", "Data")
  def handle_event_data(self, node):
    if node.attributes["Name"] == "TargetUserName":
      self.TargetUserName = node.text.lower()
  @xml_handle_element("System", "TimeCreated")
  def handle_time(self, node):
    self.TimeCreated = datetime.strptime(node.attributes["SystemTime"][:26], "%Y-%m-%dT%H:%M:%S.%f")
  def xml_handler(self):
    yield self

# Get all events. Cache for performance.
@functools.cache
def get_events(file):
  events = []
  with open(file, "rb") as f:
    for item in Parser(f).iter_from(win_event):
      events.append(item)
  return events

# Part 1 information:
def p1_general_information():
  events = get_events("SecurityLog-rev2.xml")
  # Get min time:
  min_time = min(events,key=attrgetter('TimeCreated'))
  print("Min Time: "+str(min_time.TimeCreated))

  # Get max time:
  max_time = max(events,key=attrgetter('TimeCreated'))
  print("Max Time: "+str(max_time.TimeCreated))

  # Note on time zones:
  print("The times provided by the XML are in ZULU time")
  
  print("Event count: "+str(len(events)))

def p2_4624_information():
  events = [e for e in get_events("SecurityLog-rev2.xml") if e.EventID == "4624"]
  print("4624 event count: "+str(len(events)))
  
def p2_4624_counts(user: bool):
  if user:
    print("--- Human Account Login Stats ---")
    values, counts = np.unique([e.TargetUserName for e in get_events("SecurityLog-rev2.xml") if e.EventID == "4624" and not re.match(".*\$$", e.TargetUserName)], return_counts=True)
  else:
    print("--- Machine Account Login Stats ---")
    values, counts = np.unique([e.TargetUserName for e in get_events("SecurityLog-rev2.xml") if e.EventID == "4624" and re.match(".*\$$", e.TargetUserName)], return_counts=True)
  login_counts = []
  for index, value in enumerate(values):
    login_counts.append([value, counts[index]])
  login_counts = sorted(login_counts, key=lambda dup: dup[1], reverse=True)
  print("Account count: "+str(len(login_counts)))
  print("Top 3 logins:")
  for user, count in login_counts[:3]:
    print(user + " " + str(count))
  print("-----------------")

def p2_4624_freq_chart(user: str):
  events = [pd.to_datetime(e.TimeCreated) for e in get_events("SecurityLog-rev2.xml") if e.EventID == "4624" and e.TargetUserName==user]
  df_events = pd.Series(1, index=events).resample('1h').sum()
  df_events.plot(kind='bar')
  plt.title(user+" Login Frequency By Hour")
  plt.savefig('images/4624_freq_chart_'+user+'.png', bbox_inches='tight')
  
def p3_4625_information():
  events = [e for e in get_events("SecurityLog-rev2.xml") if e.EventID == "4625"]
  print("4625 event count: "+str(len(events)))
  
  print("Failed logins:")
  for event in events:
    print(event.Computer + " " + event.TargetUserName + " " + str(event.TimeCreated));

##### Main:
p1_general_information()
p2_4624_information()
p2_4624_counts(True)
p2_4624_counts(False)
p2_4624_freq_chart("grant.larson")
p2_4624_freq_chart("matt.edwards")
p3_4625_information()