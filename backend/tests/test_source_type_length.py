from sentineltrace.parsers.windows_evtx import _source_type_from_channel


def test_long_rdp_channel_fits_db_column():
    channel = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
    st = _source_type_from_channel(channel)
    assert len(st) <= 255
    assert st.startswith("windows_")
