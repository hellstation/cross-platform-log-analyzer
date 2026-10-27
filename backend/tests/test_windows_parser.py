from sentineltrace.parsers.windows_evtx import WindowsEvtxParser

SAMPLE_4625 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Channel>Security</Channel>
    <Computer>WIN10.lab</Computer>
    <TimeCreated SystemTime="2026-01-10T12:00:00.0000000Z"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="IpAddress">192.0.2.10</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>"""


def test_parse_4625_xml():
    parser = WindowsEvtxParser()
    event = parser._parse_xml(SAMPLE_4625, "Security")
    assert event.event_id == "4625"
    assert event.username == "admin"
    assert event.source_ip == "192.0.2.10"
    assert event.authentication_result.value == "failure"
