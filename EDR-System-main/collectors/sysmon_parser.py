from xml.etree import ElementTree as ET
from typing import Dict, Any

class SysmonParser:
    """
    Parses Sysmon XML Event Logs into structured dictionaries.
    Separating logic from the collector.
    """
    @staticmethod
    def parse_event(xml_string: str) -> Dict[str, Any]:
        """
        Parses the raw XML of a Sysmon event.
        """
        result = {"EventID": None, "EventData": {}}
        try:
            root = ET.fromstring(xml_string)
            # Find EventID
            system = root.find("{http://schemas.microsoft.com/win/2004/08/events/event}System")
            if system is not None:
                event_id_elem = system.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
                if event_id_elem is not None:
                    result["EventID"] = int(event_id_elem.text)

            # Find EventData
            event_data = root.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventData")
            if event_data is not None:
                for data in event_data.findall("{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
                    key = data.get("Name")
                    val = data.text
                    if key:
                        result["EventData"][key] = val
        except Exception as e:
            # In a robust implementation, log the parsing error
            pass
            
        return result
